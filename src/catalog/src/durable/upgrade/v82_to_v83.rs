// Copyright Materialize, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

//! Repair Role rows whose stored byte image diverged from current-proto
//! retractions (database-issues#7179).
//!
//! The `v80_to_v81` migration gated its `auto_provision_source` backfill on an
//! `is_cloud` heuristic that required `mz_system` to be `ClusterVariant::Managed`.
//! On envs that didn't match, the migration silently no-opped and Role rows
//! kept their v80 byte form (no `auto_provision_source` key). Any subsequent
//! role-touching DDL then wrote a retract+insert through current protos whose
//! retraction bytes don't match the stored row, leaving the shard with a
//! stale `+1` (v80 form), a dangling `-1` (current form), and — for non-DROP
//! mutations — a live `+1` (current form). The dangling `-1` trips
//! `PersistPeek` and `run_versioned_upgrade`'s consolidation soft-assert.
//!
//! For each Role matching that fingerprint — dangling `-1` with at least one
//! parsed-equal `+1` sibling and at most one other `+1` — we write a `+1` of
//! the dangling bytes (cancels it) plus `-1`s of every parsed-equal `+1`
//! (completes the intended retraction). Anything that doesn't fit is logged
//! and left alone.

use std::collections::BTreeMap;

use mz_repr::Diff;

use crate::durable::objects::state_update::{StateUpdate, StateUpdateKindJson};
use crate::durable::persist::{Mode, Timestamp, UnopenedPersistCatalogState};
use crate::durable::upgrade::objects_v83 as v83;
use crate::durable::{CatalogError, initialize::USER_VERSION_KEY};

const FROM_VERSION: u64 = 82;
const TO_VERSION: u64 = 83;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RepairStats {
    pub repaired: usize,
    pub stale_retracted: usize,
    pub skipped_role: usize,
    pub skipped_non_role: usize,
}

pub async fn upgrade(
    unopened_catalog_state: &mut UnopenedPersistCatalogState,
    mut commit_ts: Timestamp,
) -> Result<(u64, Timestamp), CatalogError> {
    tracing::info!(
        from_version = FROM_VERSION,
        to_version = TO_VERSION,
        "running versioned Catalog upgrade (repair Role byte-form drift)",
    );

    let (repairs, stats) = compute_repairs(&unopened_catalog_state.snapshot);

    if !repairs.is_empty() {
        tracing::info!(
            repaired = stats.repaired,
            stale_retracted = stats.stale_retracted,
            "repairing Role rows left in inconsistent byte form by the v80->v81 migration's non-cloud no-op",
        );
    }
    if stats.skipped_role > 0 || stats.skipped_non_role > 0 {
        tracing::warn!(
            skipped_role = stats.skipped_role,
            skipped_non_role = stats.skipped_non_role,
            "left dangling diffs that did not fit the v80-form-drift signature; review the WARN events emitted above",
        );
    }

    let mut updates: Vec<(StateUpdateKindJson, Diff)> = repairs;
    updates.push((version_update_kind(FROM_VERSION), Diff::MINUS_ONE));
    updates.push((version_update_kind(TO_VERSION), Diff::ONE));

    if matches!(unopened_catalog_state.mode, Mode::Writable) {
        commit_ts = unopened_catalog_state
            .compare_and_append(updates, commit_ts)
            .await
            .map_err(|e| e.unwrap_fence_error())?;
    } else {
        let ts = commit_ts;
        let updates = updates
            .into_iter()
            .map(|(kind, diff)| StateUpdate { kind, ts, diff });
        commit_ts = commit_ts.step_forward();
        unopened_catalog_state.apply_updates_and_consolidate(updates)?;
    }

    unopened_catalog_state.consolidate();
    Ok((TO_VERSION, commit_ts))
}

pub(crate) fn compute_repairs(
    snapshot: &[(StateUpdateKindJson, Timestamp, Diff)],
) -> (Vec<(StateUpdateKindJson, Diff)>, RepairStats) {
    let mut role_plus_ones: BTreeMap<v83::RoleKey, Vec<RolePlusOne<'_>>> = BTreeMap::new();
    for (kind_json, _, diff) in snapshot {
        if *diff != Diff::ONE {
            continue;
        }
        let Some(role) = try_as_role(kind_json) else {
            continue;
        };
        role_plus_ones
            .entry(role.key.clone())
            .or_default()
            .push(RolePlusOne {
                bytes: kind_json,
                parsed: role,
            });
    }

    let mut repairs = Vec::new();
    let mut stats = RepairStats::default();
    for (kind_json, _, diff) in snapshot {
        if *diff == Diff::ONE {
            continue;
        }

        let Some(dangling) = try_as_role(kind_json) else {
            tracing::warn!(
                ?kind_json,
                %diff,
                "non-Role dangling diff; not repaired by the v80-form-drift migration",
            );
            stats.skipped_non_role += 1;
            continue;
        };

        if *diff != Diff::MINUS_ONE {
            tracing::warn!(
                role_name = %dangling.value.name,
                %diff,
                "Role row with unexpected diff magnitude; not repaired",
            );
            stats.skipped_role += 1;
            continue;
        }

        // For each `+1` sibling: parsed-equal to the dangling row is `stale`
        // (byte-form drift to be retracted); parsed-different is `live`. We
        // require at least one stale and at most one live.
        let siblings = role_plus_ones
            .get(&dangling.key)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut stale: Vec<&RolePlusOne<'_>> = Vec::new();
        let mut live: Option<&RolePlusOne<'_>> = None;
        let mut ambiguous_live = false;
        for sib in siblings {
            if sib.parsed.value == dangling.value {
                stale.push(sib);
            } else if live.replace(sib).is_some() {
                ambiguous_live = true;
            }
        }

        if stale.is_empty() {
            tracing::warn!(
                role_name = %dangling.value.name,
                num_siblings = siblings.len(),
                "dangling Role -1 has no parsed-equal +1 sibling; not the v80-form-drift signature",
            );
            stats.skipped_role += 1;
            continue;
        }
        if ambiguous_live {
            tracing::warn!(
                role_name = %dangling.value.name,
                num_siblings = siblings.len(),
                "Role key has multiple distinct live +1 rows; refusing to auto-repair",
            );
            stats.skipped_role += 1;
            continue;
        }

        tracing::info!(
            role_name = %dangling.value.name,
            stale_byte_forms = stale.len(),
            has_live = live.is_some(),
            "repairing v80-form-drift phantom retraction",
        );
        repairs.push((kind_json.clone(), Diff::ONE));
        for s in stale {
            if s.bytes == kind_json {
                continue;
            }
            repairs.push((s.bytes.clone(), Diff::MINUS_ONE));
            stats.stale_retracted += 1;
        }
        stats.repaired += 1;
    }

    (repairs, stats)
}

struct RolePlusOne<'a> {
    bytes: &'a StateUpdateKindJson,
    parsed: v83::Role,
}

fn try_as_role(kind_json: &StateUpdateKindJson) -> Option<v83::Role> {
    let kind: v83::StateUpdateKind = kind_json.try_to_serde().ok()?;
    match kind {
        v83::StateUpdateKind::Role(role) => Some(role),
        _ => None,
    }
}

fn version_update_kind(version: u64) -> StateUpdateKindJson {
    use crate::durable::objects::serialization::proto;
    use crate::durable::objects::state_update::StateUpdateKind;
    StateUpdateKind::Config(
        proto::ConfigKey {
            key: USER_VERSION_KEY.to_string(),
        },
        proto::ConfigValue { value: version },
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable::upgrade::objects_v83 as v83;
    use mz_repr::Diff;

    fn role_kind(
        user_id: u64,
        name: &str,
        oid: u32,
        login: Option<bool>,
        superuser: Option<bool>,
        auto_provision_source: Option<v83::AutoProvisionSource>,
    ) -> StateUpdateKindJson {
        let role = v83::Role {
            key: v83::RoleKey {
                id: v83::RoleId::User(user_id),
            },
            value: v83::RoleValue {
                name: name.to_string(),
                oid,
                attributes: v83::RoleAttributes {
                    inherit: true,
                    superuser,
                    login,
                    auto_provision_source,
                },
                membership: v83::RoleMembership { map: vec![] },
                vars: v83::RoleVars { entries: vec![] },
            },
        };
        v83::StateUpdateKind::Role(role).into()
    }

    /// Mirrors the v80-era byte form: same parsed `RoleValue` as
    /// `role_kind(.., None)` but omits the `auto_provision_source` key
    /// entirely, so the stored bytes differ.
    fn stale_role_kind_with_dropped_field(
        user_id: u64,
        name: &str,
        oid: u32,
    ) -> StateUpdateKindJson {
        use serde_json::json;
        let v = json!({
            "kind": "Role",
            "key": { "id": { "User": user_id } },
            "value": {
                "name": name,
                "oid": oid,
                "attributes": {
                    "inherit": true,
                    "superuser": null,
                    "login": null,
                    // intentionally no "auto_provision_source" key
                },
                "membership": { "map": [] },
                "vars": { "entries": [] },
            }
        });
        StateUpdateKindJson::from_serde(&v)
    }

    fn database_kind(id: u64, name: &str) -> StateUpdateKindJson {
        let db = v83::Database {
            key: v83::DatabaseKey {
                id: v83::DatabaseId::User(id),
            },
            value: v83::DatabaseValue {
                name: name.to_string(),
                owner_id: v83::RoleId::System(1),
                privileges: vec![],
                oid: 0,
            },
        };
        v83::StateUpdateKind::Database(db).into()
    }

    fn snapshot(
        rows: Vec<(StateUpdateKindJson, Diff)>,
    ) -> Vec<(StateUpdateKindJson, Timestamp, Diff)> {
        rows.into_iter()
            .map(|(kind, diff)| (kind, Timestamp::new(0), diff))
            .collect()
    }

    #[mz_ore::test]
    fn healthy_snapshot_is_a_noop() {
        let snap = snapshot(vec![
            (
                role_kind(1, "alice@example.com", 100, Some(true), None, None),
                Diff::ONE,
            ),
            (role_kind(2, "bob", 101, None, None, None), Diff::ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        assert!(repairs.is_empty());
        assert_eq!(stats, RepairStats::default());
    }

    #[mz_ore::test]
    fn production_shape_alter_login_is_repaired() {
        let live = role_kind(8, "jan@materialize.com", 20030, Some(true), None, None);
        let dangling = role_kind(8, "jan@materialize.com", 20030, None, None, None);
        let stale = stale_role_kind_with_dropped_field(8, "jan@materialize.com", 20030);

        assert_eq!(
            try_as_role(&stale).expect("parses as Role").value,
            try_as_role(&dangling).expect("parses as Role").value,
            "test fixture broken: stale and dangling must be parsed-equal",
        );
        assert_ne!(
            stale, dangling,
            "test fixture broken: stale and dangling must have different bytes",
        );

        let snap = snapshot(vec![
            (stale.clone(), Diff::ONE),
            (dangling.clone(), Diff::MINUS_ONE),
            (live, Diff::ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        assert_eq!(
            repairs,
            vec![(dangling, Diff::ONE), (stale, Diff::MINUS_ONE)],
        );
        assert_eq!(
            stats,
            RepairStats {
                repaired: 1,
                stale_retracted: 1,
                ..Default::default()
            }
        );
    }

    #[mz_ore::test]
    fn alter_changing_superuser_is_repaired() {
        let live = role_kind(11, "ops@materialize.com", 20040, None, Some(true), None);
        let dangling = role_kind(11, "ops@materialize.com", 20040, None, None, None);
        let stale = stale_role_kind_with_dropped_field(11, "ops@materialize.com", 20040);

        let snap = snapshot(vec![
            (stale.clone(), Diff::ONE),
            (dangling.clone(), Diff::MINUS_ONE),
            (live, Diff::ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        assert_eq!(
            repairs,
            vec![(dangling, Diff::ONE), (stale, Diff::MINUS_ONE)],
        );
        assert_eq!(stats.repaired, 1);
        assert_eq!(stats.stale_retracted, 1);
    }

    #[mz_ore::test]
    fn alter_changing_name_is_repaired() {
        let live = role_kind(12, "renamed@materialize.com", 20050, None, None, None);
        let dangling = role_kind(12, "original@materialize.com", 20050, None, None, None);
        let stale = stale_role_kind_with_dropped_field(12, "original@materialize.com", 20050);

        let snap = snapshot(vec![
            (stale.clone(), Diff::ONE),
            (dangling.clone(), Diff::MINUS_ONE),
            (live, Diff::ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        assert_eq!(
            repairs,
            vec![(dangling, Diff::ONE), (stale, Diff::MINUS_ONE)],
        );
        assert_eq!(stats.repaired, 1);
        assert_eq!(stats.stale_retracted, 1);
    }

    #[mz_ore::test]
    fn drop_role_shape_is_repaired() {
        let dangling = role_kind(13, "dropped@materialize.com", 20060, None, None, None);
        let stale = stale_role_kind_with_dropped_field(13, "dropped@materialize.com", 20060);

        let snap = snapshot(vec![
            (stale.clone(), Diff::ONE),
            (dangling.clone(), Diff::MINUS_ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        assert_eq!(
            repairs,
            vec![(dangling, Diff::ONE), (stale, Diff::MINUS_ONE)],
        );
        assert_eq!(
            stats,
            RepairStats {
                repaired: 1,
                stale_retracted: 1,
                ..Default::default()
            }
        );
    }

    #[mz_ore::test]
    fn dangling_minus_one_with_no_parsed_equal_plus_one_is_skipped() {
        let dangling = role_kind(20, "ghost", 200, None, None, None);
        let snap = snapshot(vec![(dangling, Diff::MINUS_ONE)]);
        let (repairs, stats) = compute_repairs(&snap);
        assert!(repairs.is_empty());
        assert_eq!(stats.skipped_role, 1);
    }

    #[mz_ore::test]
    fn dangling_minus_one_with_only_a_different_parsed_live_is_skipped() {
        let dangling = role_kind(21, "alice@materialize.com", 210, None, None, None);
        let live = role_kind(21, "alice@materialize.com", 210, Some(true), None, None);
        let snap = snapshot(vec![(dangling, Diff::MINUS_ONE), (live, Diff::ONE)]);
        let (repairs, stats) = compute_repairs(&snap);
        assert!(repairs.is_empty());
        assert_eq!(stats.skipped_role, 1);
    }

    #[mz_ore::test]
    fn ambiguous_two_distinct_live_rows_is_skipped() {
        let live_a = role_kind(22, "alice", 220, Some(true), None, None);
        let live_b = role_kind(22, "alice", 220, Some(false), Some(true), None);
        let dangling = role_kind(22, "alice", 220, None, None, None);
        let stale = stale_role_kind_with_dropped_field(22, "alice", 220);
        let snap = snapshot(vec![
            (stale, Diff::ONE),
            (live_a, Diff::ONE),
            (live_b, Diff::ONE),
            (dangling, Diff::MINUS_ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        assert!(repairs.is_empty());
        assert_eq!(stats.skipped_role, 1);
    }

    #[mz_ore::test]
    fn dangling_non_role_is_skipped() {
        let dangling = database_kind(1, "ghostdb");
        let snap = snapshot(vec![(dangling, Diff::MINUS_ONE)]);
        let (repairs, stats) = compute_repairs(&snap);
        assert!(repairs.is_empty());
        assert_eq!(stats.skipped_non_role, 1);
    }

    #[mz_ore::test]
    fn dangling_diff_other_than_minus_one_is_skipped() {
        let dangling = role_kind(30, "arjun", 20032, None, None, None);
        let stale = stale_role_kind_with_dropped_field(30, "arjun", 20032);
        let live = role_kind(30, "arjun", 20032, Some(true), None, None);
        let snap = snapshot(vec![
            (dangling, Diff::MINUS_ONE + Diff::MINUS_ONE),
            (stale, Diff::ONE),
            (live, Diff::ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        assert!(repairs.is_empty());
        assert_eq!(stats.skipped_role, 1);
    }

    #[mz_ore::test]
    fn repair_with_multiple_stale_byte_forms_retracts_all() {
        let live = role_kind(40, "alice@materialize.com", 20070, Some(true), None, None);
        let dangling = role_kind(40, "alice@materialize.com", 20070, None, None, None);
        let stale_a = stale_role_kind_with_dropped_field(40, "alice@materialize.com", 20070);
        let stale_b = stale_role_kind_with_extra_whitespace(40, "alice@materialize.com", 20070);
        assert_ne!(stale_a, stale_b);

        let snap = snapshot(vec![
            (stale_a.clone(), Diff::ONE),
            (stale_b.clone(), Diff::ONE),
            (dangling.clone(), Diff::MINUS_ONE),
            (live, Diff::ONE),
        ]);
        let (repairs, stats) = compute_repairs(&snap);
        // Retraction order is BTreeMap-dependent; assert as a set.
        let plus = repairs
            .iter()
            .filter(|(_, d)| *d == Diff::ONE)
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        let minus = repairs
            .iter()
            .filter(|(_, d)| *d == Diff::MINUS_ONE)
            .map(|(k, _)| k.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(plus, vec![dangling]);
        let expected_minus: std::collections::BTreeSet<_> =
            [stale_a, stale_b].into_iter().collect();
        assert_eq!(minus, expected_minus);
        assert_eq!(stats.repaired, 1);
        assert_eq!(stats.stale_retracted, 2);
    }

    /// A second byte form parsing to the same `RoleValue` as
    /// `stale_role_kind_with_dropped_field`, used to exercise multi-stale-row
    /// handling. Includes a stray `password: null` key that parses to nothing
    /// but changes the stored bytes.
    fn stale_role_kind_with_extra_whitespace(
        user_id: u64,
        name: &str,
        oid: u32,
    ) -> StateUpdateKindJson {
        use serde_json::json;
        let v = json!({
            "kind": "Role",
            "key": { "id": { "User": user_id } },
            "value": {
                "name": name,
                "oid": oid,
                "attributes": {
                    "inherit": true,
                    "superuser": null,
                    "login": null,
                    "auto_provision_source": null,
                    "password": null,
                },
                "membership": { "map": [] },
                "vars": { "entries": [] },
            }
        });
        StateUpdateKindJson::from_serde(&v)
    }
}
