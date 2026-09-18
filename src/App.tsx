import { useEffect, useState } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { AppRouter } from './routes/router';
import { WebSocketController } from './realtime/WebSocketController';
import { authController } from './auth/AuthController';
import { setRealtimeTransport, disposeRealtimeTransport } from './realtime/setup';
import './keys/KeyController';

const webSocketController = new WebSocketController({ authController });

export default function App(): JSX.Element {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    setRealtimeTransport({ webSocketController, autoConnect: true });
    setReady(true);
    return () => {
      disposeRealtimeTransport();
    };
  }, []);

  if (!ready) {
    // First paint before useEffect runs — render an empty shell so React
    // StrictMode's double-mount has something to attach to.
    return <div className="app-shell" />;
  }

  return (
    <BrowserRouter>
      <AppRouter />
    </BrowserRouter>
  );
}
