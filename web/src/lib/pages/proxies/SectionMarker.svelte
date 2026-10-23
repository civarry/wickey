<script lang="ts">
  interface Props {
    n: number;
  }
  let { n }: Props = $props();
</script>

<span aria-hidden="true" class="grid size-6 shrink-0 place-items-center rounded-full border border-border-strong bg-surface-2 font-mono text-xs text-text-muted">{n}</span>
