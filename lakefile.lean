import Lake
open System Lake DSL

open Lean Elab Term in
elab "systemCppLinkArgs" : term => do
  let args : Array String ← if System.Platform.isOSX then pure #["-lc++"] else do
    let compiler := (← IO.getEnv "CXX").getD "c++"
    let mut paths : Array String := #[]
    for name in ["libstdc++.so", "libc.so.6"] do
      let output ← IO.Process.output { cmd := compiler, args := #["-print-file-name=" ++ name] }
      let path := output.stdout.trimAscii.toString
      if output.exitCode != 0 || path == name || !(← System.FilePath.pathExists path) then
        throwError "cannot locate {name} using {compiler}: {output.stderr}"
      paths := paths.push path
    -- Match system C++ headers and glibc instead of Lean's older bundled sysroot.
    pure (paths.push "-lpthread")
  return Lean.toExpr args

package casbin where
  version := v!"0.2.0"
  moreLinkArgs := systemCppLinkArgs

extern_lib casbin_re2 pkg := do
  let src ← inputTextFile (pkg.dir / "native" / "regex.cpp")
  let buildSource ← inputTextFile (pkg.dir / "scripts" / "build-re2.py")
  let inputs := Job.collectArray #[src, buildSource]
  inputs.mapM fun _ => do
    let output := pkg.sharedLibDir / nameToStaticLib "casbin_re2"
    let art ← buildArtifactUnlessUpToDate output (ext := "a") (restore := true) do
      proc { cmd := "python3", args := #[(pkg.dir / "scripts" / "build-re2.py").toString,
        (← getLeanIncludeDir).toString, output.toString] }
    return art.path

@[default_target]
lean_lib Casbin where
  precompileModules := true

lean_lib CasbinTests where
  roots := #[`Test.Extended]

@[default_target]
lean_exe casbin where
  root := `Main

@[default_target, test_driver]
lean_exe casbin_test where
  root := `Test.Main
