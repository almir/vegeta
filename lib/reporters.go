package vegeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/tabwriter"
   "encoding/csv"
)

// Reporter represents any function which takes a slice of Results and
// generates a report returned as a slice of bytes and an error in case
// of failure
type Reporter func([]Result) ([]byte, error)

// ReportText returns a computed Metrics struct as aligned, formatted text
func ReportText(results []Result) ([]byte, error) {
	m := NewMetrics(results)
	out := &bytes.Buffer{}

	w := tabwriter.NewWriter(out, 0, 8, 2, '\t', tabwriter.StripEscape)
	fmt.Fprintf(w, "Requests\t[total]\t%d\n", m.Requests)
	fmt.Fprintf(w, "Duration\t[total]\t%s\n", m.Duration)
	fmt.Fprintf(w, "Latencies\t[mean, 50, 95, 99, max]\t%s, %s, %s, %s, %s\n",
		m.Latencies.Mean, m.Latencies.P50, m.Latencies.P95, m.Latencies.P99, m.Latencies.Max)
	fmt.Fprintf(w, "Bytes In\t[total, mean]\t%d, %.2f\n", m.BytesIn.Total, m.BytesIn.Mean)
	fmt.Fprintf(w, "Bytes Out\t[total, mean]\t%d, %.2f\n", m.BytesOut.Total, m.BytesOut.Mean)
	fmt.Fprintf(w, "Success\t[ratio]\t%.2f%%\n", m.Success*100)
	fmt.Fprintf(w, "Status Codes\t[code:count]\t")
	for code, count := range m.StatusCodes {
		fmt.Fprintf(w, "%s:%d  ", code, count)
	}
	fmt.Fprintln(w, "\nError Set:")
	for _, err := range m.Errors {
		fmt.Fprintln(w, err)
	}

	if err := w.Flush(); err != nil {
		return []byte{}, err
	}
	return out.Bytes(), nil
}

// ReportJSON writes a computed Metrics struct to as JSON
func ReportJSON(results []Result) ([]byte, error) {
	return json.Marshal(NewMetrics(results))
}

type ResultGroup struct {
   from int
   to int
   rate uint64
}

func ReportCSV(results []Result) ([]byte, error) {
   out := &bytes.Buffer{}

   header := []string{ "rate", "mean_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "bytesIn_B", "bytesOut_B", "success_percent" }

   w := csv.NewWriter(out)
   w.Write(header)

   resultGroups := slicesPerAttackRate(results)

   for _,resultGroup := range resultGroups {
      m := NewMetrics(results[resultGroup.from:resultGroup.to])
      w.Write(m.Csv(resultGroup.rate))
   }

   w.Flush()

   return out.Bytes(), nil
}

func slicesPerAttackRate(results []Result) ([]ResultGroup) {

   resultGroups := []ResultGroup{}

   if len(results) > 0 {
      resultGroup := ResultGroup{}
      resultGroup.from = 0
      resultGroup.to = 0
      resultGroup.rate = results[0].Rate

      for i, result := range results {
         if result.Rate != resultGroup.rate {
            resultGroup.to = i
            resultGroups = append(resultGroups, resultGroup)
            resultGroup = ResultGroup{}
            resultGroup.from = i
            resultGroup.rate = result.Rate
         }
     }
     resultGroup.to = len(results)
     resultGroups = append(resultGroups, resultGroup)
  }

  return resultGroups
}
