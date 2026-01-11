import { ApiResponse } from '@infamous-freight/shared';

export default function Home() {
  const response: ApiResponse<string> = { success: true, data: 'Welcome!' };
  return (
    <main style={{ padding: 24, fontFamily: 'sans-serif' }}>
      <h1>Infamous Freight Enterprises</h1>
      <p>Status: {response.success ? 'OK' : 'Error'}</p>
      <p>Data: {response.data}</p>
    </main>
  );
}
