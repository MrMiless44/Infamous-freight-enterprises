import type { GetServerSideProps } from "next";

type HealthProps = {
  status: any;
  ok: boolean;
};

export const getServerSideProps: GetServerSideProps<HealthProps> = async () => {
  const base = process.env.NEXT_PUBLIC_API_URL || process.env.API_BASE_URL;
  const res = await fetch(`${base}/health`);
  const json = await res.json();
  return {
    props: {
      status: json?.data ?? null,
      ok: !!json?.data?.ok,
    },
  };
};

export default function HealthPage({ status, ok }: HealthProps) {
  return (
    <main style={{ padding: 24 }}>
      <h1>API Health</h1>
      <p>OK: {ok ? "true" : "false"}</p>
      <pre>{JSON.stringify(status, null, 2)}</pre>
    </main>
  );
}
