import Casbin

open Casbin

def main : IO Unit := do
  let model := "[request_definition]\nr = sub, obj, act\n[policy_effect]\ne = some(where (p.eft == allow))\n" ++
    "[matchers]\nm = r.sub.Age >= 18 && r.obj.Owner == r.sub.Name && regexMatch(r.act, '^read{1}$')\n"
  let .ok e := Enforcer.fromText model "" | throw (IO.userError "invalid model")
  let alice := Value.object [("Name", .text "alice"), ("Age", .number 21)]
  let report := Value.object [("Owner", .text "alice")]
  let decision ← e.enforceValuesIO [alice, report, .text "read"]
  unless decision.allow do throw (IO.userError "ABAC example should allow Alice")
  IO.println s!"Alice reads her report: {decision.allow}"
