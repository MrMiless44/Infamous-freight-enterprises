import { useRouter } from "next/router";
import { useEffect, useState } from "react";

type DriverAvatarData = {
  name: string;
  state: string;
  tone: string;
  confidence: number | string;
};

function DriverAvatar({ driverId }: { driverId: string }) {
  const [avatar, setAvatar] = useState<DriverAvatarData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!driverId) return;

    let cancelled = false;
    fetch(`/api/avatars/driver/${driverId}`)
      .then((res) => {
        if (!res.ok) throw new Error("Failed to load driver avatar");
        return res.json();
      })
      .then((data: DriverAvatarData) => {
        if (!cancelled) setAvatar(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });

    return () => {
      cancelled = true;
    };
  }, [driverId]);

  if (error) {
    return <p className="text-red-600">Unable to load avatar: {error}</p>;
  }

  if (!avatar) return <p>Loading avatar…</p>;

  return (
    <div className="rounded-xl border p-4 shadow-sm">
      <h3 className="text-lg font-semibold">{avatar.name}</h3>
      <p className="text-sm text-gray-700">Status: {avatar.state}</p>
      <p className="text-sm text-gray-700">Tone: {avatar.tone}</p>
      <p className="text-sm text-gray-700">Confidence: {avatar.confidence}</p>
    </div>
  );
}

export default function DriverAvatarPage() {
  const { query } = useRouter();
  const driverId = query.id;

  if (!driverId || Array.isArray(driverId)) {
    return <p>Loading avatar…</p>;
  }

  return (
    <main className="mx-auto max-w-xl p-6">
      <DriverAvatar driverId={driverId} />
    </main>
  );
}
