import Casbin

open Casbin

def main : IO Unit := do
  let e ← Enforcer.fromFiles "examples/basic_model.conf" "examples/basic_policy.csv"
  let runtime ← RuntimeEnforcer.new e (some (← Adapter.memory e.rules))
  runtime.enableCache true 60000 100
  runtime.setWatcher (fun event => IO.println s!"Committed version {event.version}: {event.added.length} additions")
  runtime.withTransaction fun tx => do
    let _ ← tx.addPolicy ["bob", "report", "read"]
    let result ← tx.enforceEx ["bob", "report", "read"]
    unless result.allow do throw (IO.userError "transaction did not see its update")
    unless !(← runtime.enforce ["bob", "report", "read"]) do throw (IO.userError "uncommitted change leaked")
  unless ← runtime.enforce ["bob", "report", "read"] do throw (IO.userError "commit was not published")
  IO.println "Bob reads report after commit: true"
