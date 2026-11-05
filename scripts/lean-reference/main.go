// Generate matcher arithmetic expectations with the upstream govaluate version.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/casbin/govaluate"
)

func main() {
	expressions := []string{
		"2 && true", "true && 3", "!2", "2 ? 1 : 3", "1 - true", "'x' * 2", "1 in 2",
		"0xff + 1", "0X10 + 1", "01 + 2", ".5 * 2", "1. + 2", "1.e2", "(1 / 0) > 1e100", "(1 % 0) == (1 % 0)",
		"'2026-11-05'", "'2026-11-05 12:34'", "'2026-11-05 12:34:56'", "'2026-11-05T12:34:56+08:00'",
		"'2026-11-05T12:34:56Z'", "'2026-11-05T12:34:56.123Z'", "'Thu Nov 5 12:34:56 2026'",
		"2 ** 3 ** 2", "-2 ** 2", "2 ** -2", "8 | 3 & 1", "8 ^ 3 & 1", "8 & 3 ^ 1",
		"2 + 3 << 2", "64 >> 2 + 1", "2 ** 3 * 4 + 5", "10 - 3 - 2", "100 / 10 / 2",
		"true ? 1 : 2", "false ? 1 : true ? 2 : 3", "'x' + 3", "3 + 'x'", "'x' + true",
		"'a' < 'b'", "'a' == 'b'", "!false && true", "true || false && false", "1 in (1, 2, 3)",
		"'abc' =~ 'a.*'", "'abc' !~ 'z'", "(3 + 4) * 2",
	}
	for _, a := range []int{-8, -3, 0, 3, 8} {
		for _, b := range []int{1, 2, 3, 64} {
			for _, op := range []string{"%", "<<", ">>", "&", "|", "^"} {
				expressions = append(expressions, fmt.Sprintf("%d %s %d", a, op, b))
			}
		}
	}
	rows := []map[string]interface{}{}
	for _, source := range expressions {
		expr, err := govaluate.NewEvaluableExpression(source)
		var value interface{}
		if err == nil {
			value, err = expr.Evaluate(nil)
		}
		row := map[string]interface{}{"expression": source}
		if err != nil {
			row["error"] = err.Error()
		} else {
			row["expected"] = value
		}
		rows = append(rows, row)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(rows); err != nil {
		panic(err)
	}
}
