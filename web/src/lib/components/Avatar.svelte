<script lang="ts">
  interface Props {
    name: string;
    size?: 'sm' | 'md';
  }
  let { name, size = 'sm' }: Props = $props();
</script>

<span
  aria-hidden="true"
  class="grid shrink-0 place-items-center rounded-md border border-border-strong bg-surface-2 font-semibold text-text-muted {size === 'md' ? 'size-8 text-sm' : 'size-6 text-xs'}"
>{name.charAt(0).toUpperCase()}</span>
