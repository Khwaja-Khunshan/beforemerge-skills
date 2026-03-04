---
title: Split Large Contexts to Prevent Unnecessary Consumer Re-renders
description: "Putting too much state in a single React Context causes all consumers to re-render when any value changes. Split into focused contexts."
impact: HIGH
impact_description: prevents cascade re-renders across the entire component tree
tags: [performance, react, context, state-management, rerenders]
detection_grep: "createContext"
---

## Split Large Contexts to Prevent Unnecessary Consumer Re-renders

**Impact: HIGH (prevents cascade re-renders across the entire component tree)**

React Context triggers a re-render of **every** consumer whenever the context value changes — there is no built-in selector mechanism. When a single context holds many unrelated pieces of state (user data, theme, notifications, feature flags), changing any one value re-renders every component that subscribes to that context. In large applications, a single "god context" can cause hundreds of unnecessary re-renders.

**Incorrect (one giant context for all app state):**

```tsx
// ❌ Every consumer re-renders when ANY of these values change
interface AppState {
  user: User | null
  theme: 'light' | 'dark'
  notifications: Notification[]
  sidebarOpen: boolean
  locale: string
}

const AppContext = createContext<AppState & { dispatch: Dispatch }>(null!)

function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, initialState)

  // ❌ New object on every state change — every consumer re-renders
  return (
    <AppContext.Provider value={{ ...state, dispatch }}>
      {children}
    </AppContext.Provider>
  )
}

// These components ALL re-render when sidebar opens, even though they
// don't use sidebarOpen
function NavBar() {
  const { user } = useContext(AppContext)  // ❌ Re-renders on theme change too
  return <nav>{user?.name}</nav>
}

function ThemeToggle() {
  const { theme, dispatch } = useContext(AppContext)  // ❌ Re-renders on notification change
  return <button onClick={() => dispatch({ type: 'TOGGLE_THEME' })}>{theme}</button>
}
```

**Correct (split into focused, single-purpose contexts):**

```tsx
// ✅ Each context holds only related state
const AuthContext = createContext<{ user: User | null; login: () => void; logout: () => void }>(null!)
const ThemeContext = createContext<{ theme: 'light' | 'dark'; toggleTheme: () => void }>(null!)
const NotificationContext = createContext<{ notifications: Notification[]; dismiss: (id: string) => void }>(null!)
const SidebarContext = createContext<{ open: boolean; toggle: () => void }>(null!)

// ✅ Compose providers (or use a utility to reduce nesting)
function AppProviders({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <ThemeProvider>
        <NotificationProvider>
          <SidebarProvider>
            {children}
          </SidebarProvider>
        </NotificationProvider>
      </ThemeProvider>
    </AuthProvider>
  )
}

// ✅ Only re-renders when user changes
function NavBar() {
  const { user } = useContext(AuthContext)
  return <nav>{user?.name}</nav>
}

// ✅ Only re-renders when theme changes
function ThemeToggle() {
  const { theme, toggleTheme } = useContext(ThemeContext)
  return <button onClick={toggleTheme}>{theme}</button>
}
```

**Additional context:**

- A common pattern is to split context into a "state context" and a "dispatch context." Components that only call actions (dispatch) don't need to re-render when state changes.
- For complex state that many components need to read selectively, consider a state management library with selectors: Zustand, Jotai, or Redux Toolkit. These allow subscribing to specific slices of state.
- `useMemo` on the context value only helps if the individual values haven't changed. It does not help if the context holds frequently-changing values alongside stable ones.
- React DevTools Profiler can highlight which components re-render and why, making it easy to identify context-triggered re-renders.

**Detection hints:**

```bash
# Find large context definitions (look for interfaces/types with many fields)
grep -rn "createContext" src/ --include="*.tsx" --include="*.ts"
# Find components consuming context
grep -rn "useContext" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on useContext](https://react.dev/reference/react/useContext)
