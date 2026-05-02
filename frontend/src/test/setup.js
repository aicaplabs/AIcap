// Vitest global setup — wires @testing-library/jest-dom matchers
// (e.g. toBeInTheDocument, toHaveTextContent) into expect() so the
// component tests read like the rest of the React ecosystem.
import '@testing-library/jest-dom/vitest';
