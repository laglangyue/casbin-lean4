import Casbin
import Lean

open Casbin Lean

private def unwrap (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def decisionJson (d : Decision) : Json :=
  Json.mkObj [("allow", toJson d.allow), ("explain", toJson d.explain)]

private def help : String :=
  "Casbin Lean 4 core\n\n" ++
  "  casbin demo\n" ++
  "  casbin enforce MODEL.conf POLICY.csv SUBJECT OBJECT ACTION ...\n" ++
  "  casbin batch MODEL.conf POLICY.csv REQUESTS.json\n\n" ++
  "Requests follow the fields in the model. Batch input is an array of string arrays.\n" ++
  "enforce: exit 0 = allowed, 1 = denied, 2 = error. batch: exit 0 = processed, 2 = error."

private def demo : IO UInt32 := do
  let model := "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n" ++
    "[role_definition]\ng = _, _\n[policy_effect]\ne = some(where (p.eft == allow))\n" ++
    "[matchers]\nm = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act\n"
  let e ← unwrap (Enforcer.fromText model "p, reader, report, read\ng, alice, reader\n")
  for request in [["alice", "report", "read"], ["alice", "report", "write"], ["bob", "report", "read"]] do
    let result ← unwrap (e.enforceEx request)
    IO.println (Json.mkObj [("request", toJson request), ("decision", decisionJson result)]).compress
  return 0

private def run (args : List String) : IO UInt32 := do
  match args with
  | [] | ["demo"] => demo
  | ["--help"] | ["-h"] => IO.println help; return 0
  | "enforce" :: model :: policy :: request =>
    let e ← Enforcer.fromFiles model policy
    let result ← unwrap (e.enforceEx request)
    IO.println (decisionJson result).compress
    return if result.allow then 0 else 1
  | ["batch", model, policy, requestsPath] =>
    let e ← Enforcer.fromFiles model policy
    let json ← unwrap (Json.parse (← IO.FS.readFile requestsPath))
    let requests : List (List String) ← unwrap (fromJson? json)
    let decisions ← requests.mapM fun r => unwrap (e.enforceEx r)
    IO.println (Json.arr (decisions.map decisionJson).toArray).compress
    return 0
  | _ => throw (IO.userError help)

def main (args : List String) : IO UInt32 := do
  try run args
  catch error =>
    (← IO.getStderr).putStrLn s!"error: {error}"
    return 2
