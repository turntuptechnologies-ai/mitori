interface Props {
  score: number
  decidable: number
}

export function ScoreRing({ score, decidable }: Props) {
  const radius = 52
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - score / 100)

  // 進捗が低い＝痕跡が多く残っている状態なので、色で温度感を出す
  const stroke = score >= 90 ? '#4d7c62' : score >= 50 ? '#a16207' : '#9f4436'

  return (
    <div className="flex items-center gap-5">
      <svg width="128" height="128" viewBox="0 0 128 128" className="shrink-0">
        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          strokeWidth="10"
          className="stroke-stone-200 dark:stroke-stone-800"
        />
        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          strokeWidth="10"
          stroke={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 64 64)"
          style={{ transition: 'stroke-dashoffset 0.6s ease-out' }}
        />
        <text
          x="64"
          y="62"
          textAnchor="middle"
          className="fill-stone-900 dark:fill-stone-100"
          style={{ fontSize: 30, fontWeight: 600 }}
        >
          {score}
        </text>
        <text
          x="64"
          y="82"
          textAnchor="middle"
          className="fill-stone-500 dark:fill-stone-400"
          style={{ fontSize: 13 }}
        >
          %
        </text>
      </svg>
      <div className="text-sm leading-relaxed">
        <p className="font-semibold text-stone-800 dark:text-stone-200">自動判定の進捗</p>
        <p className="mt-1 text-stone-600 dark:text-stone-400">
          DNS から観測できる痕跡のうち、
          <br />
          {decidable} 件を判定しました
        </p>
        <p className="mt-2 text-xs text-stone-500 dark:text-stone-500">
          100% でも手放してよいとは限りません。
          <br />
          下の手動確認項目と併せて判断してください。
        </p>
      </div>
    </div>
  )
}
