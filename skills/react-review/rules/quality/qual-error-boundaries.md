---
title: Add Error Boundaries Around Unreliable UI Sections
description: "Without error boundaries, a single component crash unmounts the entire React tree. Wrap unreliable sections so failures are isolated and recoverable."
impact: MEDIUM
impact_description: prevents full-app crashes from isolated component errors
tags: [quality, react, error-boundaries, reliability, error-handling]
detection_grep: "componentDidCatch"
---

## Add Error Boundaries Around Unreliable UI Sections

**Impact: MEDIUM (prevents full-app crashes from isolated component errors)**

When a React component throws during rendering, React unmounts the entire component tree by default — the user sees a blank white screen. Error boundaries catch rendering errors in their child tree and display a fallback UI instead, keeping the rest of the application functional. Without them, a bug in a single widget, chart, or third-party embed takes down the entire page.

**Incorrect (no error boundaries — one crash kills the whole app):**

```tsx
// ❌ If AnalyticsChart throws (bad data, third-party lib error),
// the entire app goes white
function Dashboard() {
  return (
    <div>
      <Header />
      <Sidebar />
      <AnalyticsChart data={data} />  {/* crash here = blank page */}
      <RecentActivity />
      <Footer />
    </div>
  )
}
```

**Correct (error boundaries isolate failures):**

```tsx
// ✅ Reusable error boundary component (class component — required by React API)
class ErrorBoundary extends React.Component<
  { fallback: ReactNode; children: ReactNode },
  { hasError: boolean }
> {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Log to error reporting service
    reportError(error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback
    }
    return this.props.children
  }
}

// ✅ Wrap unreliable sections — rest of the app keeps working
function Dashboard() {
  return (
    <div>
      <Header />
      <Sidebar />
      <ErrorBoundary fallback={<p>Chart failed to load.</p>}>
        <AnalyticsChart data={data} />
      </ErrorBoundary>
      <ErrorBoundary fallback={<p>Activity feed unavailable.</p>}>
        <RecentActivity />
      </ErrorBoundary>
      <Footer />
    </div>
  )
}
```

**With react-error-boundary (popular library with hooks API):**

```tsx
import { ErrorBoundary } from 'react-error-boundary'

function Dashboard() {
  return (
    <div>
      <Header />
      <ErrorBoundary
        fallbackRender={({ error, resetErrorBoundary }) => (
          <div role="alert">
            <p>Something went wrong: {error.message}</p>
            <button onClick={resetErrorBoundary}>Try again</button>
          </div>
        )}
        onError={(error, info) => reportError(error, info)}
      >
        <AnalyticsChart data={data} />
      </ErrorBoundary>
      <Footer />
    </div>
  )
}
```

**Additional context:**

- Error boundaries only catch errors during rendering, lifecycle methods, and constructors of child components. They do not catch errors in event handlers, async code, or the error boundary itself. Use `try/catch` for those.
- Place error boundaries at strategic points: around each independent feature section, around third-party components, and at the app root as a last resort.
- Always log caught errors to an error reporting service (Sentry, Datadog, etc.) in `componentDidCatch` or `onError`.
- The `react-error-boundary` package provides `useErrorBoundary()` hook for triggering error boundaries from event handlers and async code.

**Detection hints:**

```bash
# Check if any error boundaries exist in the project
grep -rn "componentDidCatch\|ErrorBoundary\|getDerivedStateFromError" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on error boundaries](https://react.dev/reference/react/Component#catching-rendering-errors-with-an-error-boundary)
