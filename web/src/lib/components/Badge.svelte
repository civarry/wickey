<script lang="ts">
  interface Props {
    /**
     * 'limit' = token cap reached, 'review' = usage counters went backwards, 'tampered' = marked
     * cleaned up while still active (the DB was edited).
     * 'ready', 'attention', 'danger' and 'neutral' are plain tones for other pages; pass `label` with them.
     */
    status: 'active' | 'expired' | 'cleaned' | 'tampered' | 'limit' | 'review' | 'ready' | 'attention' | 'danger' | 'neutral';
    /** Replaces the default text. */
    label?: string;
  }
  let { status, label }: Props = $props();

  const look = {
    active: { cls: 'border-accent-border bg-accent-bg text-accent-text', text: 'Active' },
    expired: { cls: 'border-warn-border bg-warn-bg text-warn-text', text: 'Expired' },
    cleaned: { cls: 'border-border-strong bg-surface-2 text-text-muted', text: 'Cleaned up' },
    tampered: { cls: 'border-danger-border bg-danger-bg text-danger-text', text: 'Tampered' },
    limit: { cls: 'border-danger-border bg-danger-bg text-danger-text', text: 'Limit reached' },
    review: { cls: 'border-danger-border bg-danger-bg text-danger-text', text: 'Needs review' },
    ready: { cls: 'border-accent-border bg-accent-bg text-accent-text', text: 'Ready' },
    attention: { cls: 'border-warn-border bg-warn-bg text-warn-text', text: 'Check' },
    danger: { cls: 'border-danger-border bg-danger-bg text-danger-text', text: 'Problem' },
    neutral: { cls: 'border-border-strong bg-surface-2 text-text-muted', text: 'Skipped' },
  };
</script>

<span
  data-status={status}
  class="inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-xs font-medium whitespace-nowrap {look[status].cls}"
>
  <span class="size-1.5 rounded-full bg-current" aria-hidden="true"></span>
  {label ?? look[status].text}
</span>
