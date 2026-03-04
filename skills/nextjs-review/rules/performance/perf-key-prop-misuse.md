---
title: Use Stable, Unique Keys for List Items (Never Index)
description: "Using array indices as key props causes incorrect state preservation, UI corruption, and degraded performance when lists are reordered or filtered."
impact: MEDIUM
impact_description: prevents incorrect component state, UI corruption, and inefficient re-renders in lists
tags: [performance, react, keys, lists, rendering, nextjs]
detection_grep: "key=\\{index\\}|key=\\{i\\}|\\.map\\("
---

## Use Stable, Unique Keys for List Items (Never Index)

**Impact: MEDIUM (prevents incorrect component state, UI corruption, and inefficient re-renders in lists)**

React uses `key` props to track which list items changed, were added, or removed. When you use array indices (`key={index}`), React associates state with the position, not the item. If the list is reordered, filtered, or has items added/removed at the beginning, input values stick to the wrong items, animations break, and components re-mount unnecessarily.

**Incorrect (index as key):**

```tsx
// ❌ Index keys cause state to stick to the wrong item when list changes
function TodoList({ todos, onRemove }) {
  return (
    <ul>
      {todos.map((todo, index) => (
        <li key={index}> {/* If todo[0] is removed, todo[1] gets todo[0]'s state */}
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}

// ❌ Random keys force React to re-mount everything every render
{items.map(item => (
  <Card key={Math.random()} item={item} /> // Destroys and recreates on every render!
))}

// ❌ Non-unique keys cause siblings to be confused
{users.map(user => (
  <UserCard key={user.name} user={user} /> // Names aren't unique!
))}
```

**Correct (stable, unique keys):**

```tsx
// ✅ Use the item's unique identifier
function TodoList({ todos, onRemove }) {
  return (
    <ul>
      {todos.map(todo => (
        <li key={todo.id}> {/* Stable: follows the item, not the position */}
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}

// ✅ Database IDs, UUIDs, or slugs are ideal keys
{posts.map(post => <PostCard key={post.id} post={post} />)}
{products.map(product => <ProductRow key={product.sku} product={product} />)}
{pages.map(page => <NavLink key={page.slug} href={page.slug} />)}

// ✅ Composite key when no single unique field exists
{events.map(event => (
  <EventRow key={`${event.date}-${event.venue}-${event.time}`} event={event} />
))}
```

**When `key={index}` is acceptable:**

- Static lists that never reorder, filter, or have items added/removed
- Lists of display-only items with no internal state (no inputs, no animations)
- Simple lists like `['Home', 'About', 'Contact'].map((label, i) => <span key={i}>{label}</span>)`

**The symptom to watch for:** users report that "input values jump around" or "the wrong item gets deleted" after reordering or filtering a list. This is almost always an index key bug.

**Detection hints:**

```bash
# Find index used as key
grep -rn "key={index}\|key={i}\|key={idx}" src/ --include="*.tsx" --include="*.jsx"
# Find .map without key (React will warn, but catch it early)
grep -rn "\.map(" src/ --include="*.tsx" -A 2 | grep -v "key="
```

Reference: [React Docs: Why does React need keys?](https://react.dev/learn/rendering-lists#why-does-react-need-keys)
