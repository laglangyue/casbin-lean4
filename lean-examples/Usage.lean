import Casbin

open Casbin

private def unwrap (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

def main : IO Unit := do
  let original ← Enforcer.fromFiles "examples/rbac_model.conf" "examples/rbac_policy.csv"
  let first ← unwrap (original.enforceEx ["alice", "data2", "write"])
  IO.println s!"Alice writes data2: {repr first}"
  let (updated, changed) ← unwrap (original.addPolicy ["bob", "data1", "write"])
  IO.println s!"Added Bob's policy: {changed}"
  let result ← unwrap (updated.enforceEx ["bob", "data1", "write"])
  IO.println s!"Bob writes data1: {repr result}"
  let before ← unwrap (original.enforce ["bob", "data1", "write"])
  IO.println s!"Original state still denies Bob: {!before}"
