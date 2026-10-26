import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';

describe('DevShield public app', () => {
  it('renders the landing page and primary call to action', () => {
    const queryClient = new QueryClient();
    render(<QueryClientProvider client={queryClient}><BrowserRouter><App /></BrowserRouter></QueryClientProvider>);
    expect(screen.getByText(/your code deserves a/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /start analyzing/i })).toBeInTheDocument();
  });
});
