import React from 'react';
import ReactDOM from 'react-dom/client';
import { HelmetProvider } from 'react-helmet-async';
import '@fontsource/syne/700.css';
import '@fontsource/manrope/400.css';
import '@fontsource/manrope/700.css';
import '@fontsource/jetbrains-mono/400.css';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <HelmetProvider>
      <App />
    </HelmetProvider>
  </React.StrictMode>
);