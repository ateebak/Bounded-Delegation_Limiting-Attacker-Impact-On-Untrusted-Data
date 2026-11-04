"""Progent-v3-style approver (our reimplementation, D-038): expansion judgment and approver modes."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments/harness"))
from progent_approver import expansion, Approver

READ = {"read_file": [(100, 0, {"file_path": {"type": "string", "enum": ["bill.txt"]}}, 0)]}
PAY = {**READ, "send_money": [(100, 0, {"recipient": {"type": "string", "enum": ["GB94X"]}, "amount": {"type": "number", "enum": [98.7]}}, 0)]}
PAY_ATK = {**READ, "send_money": [(100, 0, {"recipient": {"type": "string", "enum": ["GB94X"]}, "amount": {"type": "number", "enum": [987]}}, 0)]}
LEGIT = {"send_money": {"recipient": "GB94X", "amount": 98.7}}


def test_new_tool_is_expansion_same_policy_is_narrowing():
    assert expansion(READ, PAY) and not expansion(PAY, PAY)


def test_changed_value_is_expansion():
    assert expansion(PAY, PAY_ATK)


def test_restricting_an_open_rule_is_narrowing():
    assert not expansion({"read_file": [(100, 0, {}, 0)]}, READ)


def test_removing_a_forbid_rule_is_expansion():
    forbid = {"send_money": [(50, 1, {"recipient": {"type": "string", "enum": ["X"]}}, 0)]}
    assert expansion(forbid, {"send_money": []})


def test_approver_modes():
    assert Approver("auto_deny").approve(expansion(READ, PAY)) is False
    assert Approver("auto_approve").approve(expansion(READ, PAY)) is True
    m = Approver("manual", "perfect", legit=LEGIT)
    assert m.approve(expansion(READ, PAY)) is True          # legitimate values
    assert m.approve(expansion(PAY, PAY_ATK)) is False      # attacker amount
    assert m.approve(expansion(READ, {"send_money": [(100, 0, {}, 0)]})) is False   # sensitive args left open
    assert m.prompts == 3
    assert Approver("manual", "rubber_stamp").approve(expansion(PAY, PAY_ATK)) is True
