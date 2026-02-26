import { render, screen } from '@testing-library/react';
import App from './App';

test('renders damera portal title', () => {
  render(<App />);
  const titleElement = screen.getByText(/damera corp\. careers portal/i);
  expect(titleElement).toBeInTheDocument();
});
