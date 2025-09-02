tsx
// LOGOS Resonance Analytics Frontend
// Автор: LOGOS Core Dev

import React, { useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface SigmaData {
  timestamp: number;
  sigma: number;
  symbol?: string; // Для Λ0
}

export default function ResonanceAnalytics() {
  const [data, setData] = useState<SigmaData[]>([]);
  const [timestamp, setTimestamp] = useState(0);
  const [latestSigma, setLatestSigma] = useState<number | null>(null);
  const [activityLevel, setActivityLevel] = useState("stable");
  const [error, setError] = useState<string | null>(null);
  const lambdaZero = "Λ0";

  useEffect(() => {
    const interval = setInterval(() => {
      fetch("/api/sigma", {
        headers: { Authorization: `Bearer ${process.env.REACT_APP_API_TOKEN}` }, // Токен для безопасности
      })
        .then((res) => {
          if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
          return res.json();
        })
        .then((json) => {
          // Валидация данных
          if (!json || typeof json.timestamp !== "number" || typeof json.sigma !== "number") {
            throw new Error("Invalid API response");
          }
          const validatedData: SigmaData = {
            timestamp: json.timestamp,
            sigma: json.sigma,
            symbol: json.symbol || "unknown",
          };
          setData((prev) => [...prev.slice(-99), validatedData]);
          setTimestamp(json.timestamp);
          setLatestSigma(json.sigma);
          setActivityLevel(json.sigma > 5.0 ? "high" : json.sigma < -5.0 ? "low" : "stable");
          logEvent(`[FETCH] Sigma=${json.sigma}, Symbol=${json.symbol || "none"}`);
          setError(null);
        })
        .catch((err) => {
          setError(`Ошибка загрузки данных: ${err.message}`);
          logEvent(`[ERROR] Fetch failed: ${err.message}`);
        });
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const logEvent = (message: string) => {
    // Логирование для resonance_analyzer.py
    const entry = {
      event: "resonance_analytics",
      message,
      timestamp: Math.floor(Date.now() / 1000),
    };
    // Предполагается, что логи отправляются в API или файл
    fetch("/api/log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(entry),
    }).catch((err) => console.error("Log error:", err));
  };

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-xl font-bold">Resonance Σ(t) Monitoring</h1>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardContent className="p-4 space-y-2">
          <p className="text-sm text-muted-foreground">
            Последняя фаза: <strong>{latestSigma?.toFixed(4) ?? "N/A"}</strong>
          </p>
          <p className="text-sm">
            Активность сети: <span className="font-semibold">{activityLevel}</span>
          </p>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis
                dataKey="timestamp"
                tickFormatter={(ts) => new Date(ts * 1000).toLocaleTimeString()}
              />
              <YAxis domain={[-10, 10]} />
              <Tooltip
                labelFormatter={(ts) => new Date(ts * 1000).toLocaleString()}
                formatter={(value: number, name: string, props: any) => [
                  value.toFixed(4),
                  props.payload.symbol === lambdaZero ? "Λ0 Sigma" : "Sigma",
                ]}
              />
              <Line
                type="monotone"
                dataKey="sigma"
                stroke={(d) => (d.symbol === lambdaZero ? "#FFD700" : "#8884d8")}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={() => {
          setData([]);
          logEvent("[RESET] График очищен");
        }}>
          Очистить график
        </Button>
      </div>
    </div>
  );
}

