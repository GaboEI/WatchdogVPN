from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from node_groups.models import NodeGroup, NodeGroupSelectionMode
from node_groups.store import NodeGroupStore, NodeGroupStoreError


class NodeGroupStoreCrudTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.store = NodeGroupStore(Path(self.tmpdir.name) / "node_groups.json")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_add_then_get(self) -> None:
        self.store.add(NodeGroup(name="paris"))

        self.assertEqual(self.store.get("paris"), NodeGroup(name="paris"))

    def test_get_missing_returns_none(self) -> None:
        self.assertIsNone(self.store.get("missing"))

    def test_list_returns_all_groups(self) -> None:
        self.store.add(NodeGroup(name="paris"))
        self.store.add(NodeGroup(name="berlin"))

        names = sorted(group.name for group in self.store.list())

        self.assertEqual(names, ["berlin", "paris"])

    def test_add_is_upsert_by_name(self) -> None:
        self.store.add(NodeGroup(name="paris", enabled=True))
        self.store.add(NodeGroup(name="paris", enabled=False))

        groups = self.store.list()
        self.assertEqual(len(groups), 1)
        self.assertFalse(groups[0].enabled)

    def test_update_is_an_alias_for_add(self) -> None:
        self.store.add(NodeGroup(name="paris", enabled=True))
        self.store.update(NodeGroup(name="paris", enabled=False))

        self.assertFalse(self.store.get("paris").enabled)

    def test_remove(self) -> None:
        self.store.add(NodeGroup(name="paris"))
        self.store.remove("paris")

        self.assertIsNone(self.store.get("paris"))

    def test_remove_missing_is_a_noop(self) -> None:
        self.store.remove("missing")  # must not raise

    def test_persists_across_store_instances(self) -> None:
        self.store.add(NodeGroup(name="paris", member_profile_ids=["p1"]))

        reopened = NodeGroupStore(self.store.path)
        self.assertEqual(reopened.get("paris").member_profile_ids, ["p1"])

    def test_never_persists_invalid_state_on_disk(self) -> None:
        # A store bug that tried to write an invalid group must fail before
        # touching disk, not leave a corrupt file behind.
        path = self.store.path
        self.store.add(NodeGroup(name="paris"))
        raw_before = path.read_text(encoding="utf-8")

        with self.assertRaises(Exception):
            # Constructing an invalid NodeGroup raises before add() is even
            # reachable - this documents that guarantee explicitly.
            NodeGroup(name="Bad Name!")

        self.assertEqual(path.read_text(encoding="utf-8"), raw_before)


class NodeGroupStoreMembershipMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.store = NodeGroupStore(Path(self.tmpdir.name) / "node_groups.json")
        self.store.add(NodeGroup(name="paris"))

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_add_member_profile(self) -> None:
        result = self.store.add_member_profile("paris", "p1")

        self.assertEqual(result.member_profile_ids, ["p1"])
        self.assertEqual(self.store.get("paris").member_profile_ids, ["p1"])

    def test_add_member_profile_is_idempotent(self) -> None:
        self.store.add_member_profile("paris", "p1")
        result = self.store.add_member_profile("paris", "p1")

        self.assertEqual(result.member_profile_ids, ["p1"])

    def test_remove_member_profile(self) -> None:
        self.store.add_member_profile("paris", "p1")
        result = self.store.remove_member_profile("paris", "p1")

        self.assertEqual(result.member_profile_ids, [])

    def test_remove_member_profile_not_present_is_a_noop(self) -> None:
        result = self.store.remove_member_profile("paris", "p1")

        self.assertEqual(result.member_profile_ids, [])

    def test_add_member_profile_raises_on_missing_group(self) -> None:
        with self.assertRaises(NodeGroupStoreError):
            self.store.add_member_profile("missing", "p1")

    def test_set_selection_manual(self) -> None:
        result = self.store.set_selection("paris", NodeGroupSelectionMode.MANUAL, "p1")

        self.assertEqual(result.selection_mode, NodeGroupSelectionMode.MANUAL)
        self.assertEqual(result.manual_profile_id, "p1")

    def test_set_selection_manual_without_profile_id_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            self.store.set_selection("paris", NodeGroupSelectionMode.MANUAL)

    def test_set_selection_auto_clears_manual_profile_id(self) -> None:
        self.store.set_selection("paris", NodeGroupSelectionMode.MANUAL, "p1")
        result = self.store.set_selection("paris", NodeGroupSelectionMode.AUTO)

        self.assertEqual(result.selection_mode, NodeGroupSelectionMode.AUTO)
        self.assertIsNone(result.manual_profile_id)

    def test_set_selection_raises_on_missing_group(self) -> None:
        with self.assertRaises(NodeGroupStoreError):
            self.store.set_selection("missing", NodeGroupSelectionMode.AUTO)

    def test_mutation_does_not_disturb_other_groups(self) -> None:
        self.store.add(NodeGroup(name="berlin", member_profile_ids=["b1"]))

        self.store.add_member_profile("paris", "p1")

        self.assertEqual(self.store.get("berlin").member_profile_ids, ["b1"])


class NodeGroupStoreOnDiskShapeTests(unittest.TestCase):
    def test_store_file_is_a_plain_json_array(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "node_groups.json"
            store = NodeGroupStore(path)
            store.add(NodeGroup(name="paris"))

            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsInstance(raw, list)
            self.assertEqual(raw[0]["name"], "paris")


if __name__ == "__main__":
    unittest.main()
