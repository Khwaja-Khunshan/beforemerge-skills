---
title: Never Use Array Index as Key for Dynamic Lists
description: "Using array index as key in lists that can be reordered, filtered, or inserted into causes React to mismap state to the wrong items, creating subtle and hard-to-debug UI bugs."
impact: MEDIUM
impact_description: prevents state corruption and incorrect UI rendering in dynamic lists
tags: [quality, react, key-prop, lists, reconciliation]
detection_grep: "key={index}"
---

## Never Use Array Index as Key for Dynamic Lists

**Impact: MEDIUM (prevents state corruption and incorrect UI rendering in dynamic lists)**

React uses the `key` prop to track which items in a list have changed, been added, or been removed during reconciliation. When you use the array index as the key and the list can be reordered, filtered, sorted, or have items inserted/removed, React associates component state (input values, focus, animation state, selection) with the wrong items. This causes inputs to show stale values, animations to play on the wrong elements, and checkboxes to appear checked/unchecked incorrectly.

**Incorrect (array index as key in a dynamic list):**

```tsx
function TodoList({ todos, onRemove }: TodoListProps) {
  return (
    <ul>
      {todos.map((todo, index) => (
        // ❌ When a todo is removed from the middle, all subsequent items
        // shift indices — React reuses the wrong DOM nodes and state
        <li key={index}>
          <input
            type="checkbox"
            checked={todo.done}
            onChange={() => toggleTodo(todo.id)}
          />
          {/* If todo at index 2 is removed, index 3 becomes index 2,
              and its checkbox state comes from the old index 2 */}
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}
```

**Correct (use a stable, unique identifier as key):**

```tsx
function TodoList({ todos, onRemove }: TodoListProps) {
  return (
    <ul>
      {todos.map((todo) => (
        // ✅ Stable unique ID — React correctly tracks each item
        // through reorders, insertions, and deletions
        <li key={todo.id}>
          <input
            type="checkbox"
            checked={todo.done}
            onChange={() => toggleTodo(todo.id)}
          />
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}
```

**Additional context:**

- Array index as key is acceptable **only** when all three conditions are met: (1) the list is static and never reordered, (2) items are never inserted or removed from the middle, and (3) items have no local state or uncontrolled inputs.
- Good key sources: database IDs, UUIDs, unique slugs, or any value that is stable and unique within the list.
- If items lack a natural unique ID, generate one when the item is created (e.g., `crypto.randomUUID()`) and store it with the item — do not generate it during render.
- The React DevTools "Highlight updates" feature can help visualize when incorrect keys cause unexpected re-renders.

**Detection hints:**

```bash
# Find index used as key prop
grep -rn "key={index}\|key={i}\|key={idx}" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on why keys matter](https://react.dev/learn/rendering-lists#why-does-react-need-keys)
