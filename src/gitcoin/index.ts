import type { HexString } from "@/util/typing";

interface GitcoinPassportResponse {
  address: string;
  score: string;
  status: string;
  last_score_timestamp: string;
  expiration_date: string;
  evidence: any;
  error: any;
  stamp_scores: { [key: string]: number };
}

export const fetchGitcoinPassportScore = async (
  address: HexString
): Promise<number> => {
  const response = await fetch(
    "https://api.scorer.gitcoin.co/registry/submit-passport",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-KEY": import.meta.env.VITE_GITCOIN_API_KEY, // 使用你的 API Key
      },
      body: JSON.stringify({
        address, // 使用你的 address
        scorer_id: import.meta.env.VITE_GITCOIN_SCORE_ID,
      }),
    }
  );

  if (!response.ok) {
    console.error("Failed to fetch score:", response.statusText);
    return 0;
  }

  const data: GitcoinPassportResponse = await response.json();
  return parseFloat(data.score); // score 轉為 number
};
