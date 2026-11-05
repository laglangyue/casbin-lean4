import Std.Time

namespace Casbin

private def timestampFormat : Std.Time.GenericFormat (.only Std.Time.TimeZone.UTC) :=
  datespec("uuuu-MM-dd HH:mm:ss")

def currentTime : IO String := do
  let timestamp ← Std.Time.Timestamp.now
  return timestampFormat.format (Std.Time.DateTime.ofTimestampWithZone timestamp Std.Time.TimeZone.UTC)

def timeMatchAt (now startTime endTime : String) : Except String Bool := do
  let instant ← timestampFormat.parse now
  if startTime != "_" then
    let start ← timestampFormat.parse startTime
    if !(start.toTimestamp < instant.toTimestamp) then return false
  if endTime != "_" then
    let finish ← timestampFormat.parse endTime
    if !(instant.toTimestamp < finish.toTimestamp) then return false
  return true

def timeMatch (startTime endTime : String) : IO (Except String Bool) := do
  return timeMatchAt (← currentTime) startTime endTime

/-- Govaluate represents recognized date literals as Unix seconds. -/
def expressionTime (source : String) : Option Float := do
  if !source.contains '-' && !source.contains ':' then none
  else
    let formats : List (Std.Time.GenericFormat (.only Std.Time.TimeZone.UTC)) := [
      datespec("uuuu-MM-dd"), datespec("uuuu-MM-dd HH:mm"), datespec("uuuu-MM-dd HH:mm:ss"),
      datespec("EEE MMM d HH:mm:ss uuuu"), datespec("EEE MMM  d HH:mm:ss uuuu")]
    let zoned : List (Std.Time.GenericFormat .any) := [
      datespec("uuuu-MM-dd'T'HH:mm:ssXXX"), datespec("uuuu-MM-dd'T'HH:mm:ss.SSSSSSSSSXXX"),
      datespec("uuuu-MM-dd HH:mm:ssxxx"), datespec("uuuu-MM-dd'T'HHXX"),
      datespec("uuuu-MM-dd'T'HH:mmXX"), datespec("uuuu-MM-dd'T'HH:mm:ssXX"),
      datespec("uuuu-MM-dd'T'HH:mm:ss.SSSSSSSSSXX"),
      datespec("EEE MMM d HH:mm:ss zzz uuuu"), datespec("EEE MMM  d HH:mm:ss zzz uuuu"),
      datespec("EEE MMM dd HH:mm:ss xx uuuu")]
    let pieces := source.splitOn "."
    let adjusted := Id.run do
      if pieces.length != 2 then return source
      let tail := (pieces[1]?.getD "").toList
      let fraction := tail.takeWhile Char.isDigit
      if fraction.isEmpty then return source
      let digits := fraction.take 9 ++ List.replicate (9 - fraction.length) '0'
      return pieces.headD "" ++ "." ++ String.ofList digits ++ String.ofList (tail.drop fraction.length)
    let parsed := formats.filterMap (fun format => (format.parse source).toOption) ++
      (if [18, 21, 24, 25, 31, 34, 35].contains source.length then
        zoned.filterMap (fun format => (format.parse adjusted).toOption) else [])
    let value ← parsed.head?
    return value.toTimestamp.toSecondsSinceUnixEpoch.val.toFloat

end Casbin
