import Casbin.Value

namespace Casbin

structure Config where
  entries : List (String × String × String) := []
  deriving Repr

private def configKey (key : String) : String × String :=
  match key.splitOn "::" with
  | [name] => ("default", name)
  | domain :: rest => (domain, String.intercalate "::" rest)
  | [] => ("default", "")

def Config.addConfig (config : Config) (sectionName option value : String) : Config × Bool :=
  let sectionName := if sectionName.isEmpty then "default" else sectionName
  let alreadyPresent := config.entries.any (fun (s, o, _) => s == sectionName && o == option)
  ({ entries := config.entries.filter (fun (s, o, _) => s != sectionName || o != option) ++ [(sectionName, option, value)] }, !alreadyPresent)

def Config.get (config : Config) (key : String) : String :=
  let (sectionName, option) := configKey key
  ((config.entries.find? (fun (s, o, _) => s == sectionName && o == option)).map (fun (_, _, value) => value)).getD ""
def Config.set (config : Config) (key value : String) : Except String Config := do
  if key.isEmpty then throw "config key is empty"
  let (sectionName, option) := configKey key
  return (config.addConfig sectionName option value).1
def Config.string (config : Config) (key : String) : String := config.get key
def Config.strings (config : Config) (key : String) : List String :=
  let value := config.get key
  if value.isEmpty then [] else value.splitOn ","
def Config.bool (config : Config) (key : String) : Except String Bool :=
  match config.get key with
  | "1" | "t" | "T" | "true" | "TRUE" | "True" => .ok true
  | "0" | "f" | "F" | "false" | "FALSE" | "False" => .ok false
  | _ => .error "invalid boolean config value"
def Config.int (config : Config) (key : String) : Except String Int :=
  match (config.get key).toInt? with | some value => .ok value | none => .error "invalid integer config value"
def Config.int64 (config : Config) (key : String) : Except String Int64 := do
  let value ← config.int key
  if value < -9223372036854775808 || value > 9223372036854775807 then throw "integer config value overflows int64"
  return Int64.ofInt value
def Config.float64 (config : Config) (key : String) : Except String Float := parseNumber (config.get key)

def Config.parse (source : String) : Except String Config := do
  let mut config : Config := {}
  let mut sectionName := "default"
  let mut pending := ""
  for raw in source.splitOn "\n" do
    let line := raw.trimAscii.toString
    if line.isEmpty || line.startsWith "#" || line.startsWith ";" then continue
    if line.endsWith "\\" then
      pending := pending ++ String.ofList (line.toList.take (line.length - 1))
      continue
    let line := pending ++ line
    pending := ""
    if line.startsWith "[" && line.endsWith "]" then
      sectionName := String.ofList (line.toList.drop 1 |>.take (line.length - 2))
    else
      let parts := line.splitOn "="
      if parts.length < 2 then throw s!"invalid config entry: {line}"
      let key := (parts.headD "").trimAscii.toString
      if key.isEmpty then throw "empty config option"
      let value := (String.intercalate "=" (parts.drop 1)).trimAscii.toString
      config := (config.addConfig sectionName key value).1
  if !pending.isEmpty then throw "unterminated config continuation"
  return config

def Config.fromFile (path : System.FilePath) : IO Config := do
  match Config.parse (← IO.FS.readFile path) with
  | .ok config => return config | .error error => throw (IO.userError error)

end Casbin
