<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';

  type Variant = 'primary' | 'secondary' | 'warn' | 'danger' | 'ghost';

  interface Props extends Omit<HTMLButtonAttributes, 'class' | 'type'> {
    variant?: Variant;
    size?: 'sm' | 'md';
    type?: 'button' | 'submit' | 'reset';
    /** Shows `busyLabel` (if given), blocks clicks and marks the button aria-busy. */
    busy?: boolean;
    busyLabel?: string;
    /** Square button with only an icon. Then `aria-label` is required. */
    iconOnly?: boolean;
    class?: string;
    children: Snippet;
  }

  type IconOnlyProps = Props & ({ iconOnly: true; 'aria-label': string } | { iconOnly?: false });

  let {
    variant = 'secondary',
    size = 'md',
    type = 'button',
    busy = false,
    busyLabel,
    iconOnly = false,
    disabled = false,
    class: extra = '',
    children,
    ...rest
  }: IconOnlyProps = $props();

  const variants: Record<Variant, string> = {
    primary: 'bg-accent text-ink hover:brightness-110 border-transparent',
    secondary: 'bg-surface-2 text-text border-border-strong hover:bg-border',
    warn: 'bg-warn text-ink hover:brightness-110 border-transparent',
    danger: 'bg-danger text-ink hover:brightness-110 border-transparent',
    ghost: 'bg-transparent text-text-muted border-transparent hover:bg-surface-2 hover:text-text',
  };
  const sizes = { sm: 'h-8 text-[13px]', md: 'h-9 text-sm' };
  const pad = $derived(iconOnly ? (size === 'sm' ? 'w-8' : 'w-9') : size === 'sm' ? 'px-2.5' : 'px-3.5');
</script>

<button
  {...rest}
  {type}
  disabled={disabled || busy}
  aria-busy={busy || undefined}
  class="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-md border font-medium whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-45 aria-busy:cursor-progress aria-busy:opacity-70 {variants[variant]} {sizes[size]} {pad} {extra}"
>
  {#if busy && busyLabel}{busyLabel}{:else}{@render children()}{/if}
</button>
