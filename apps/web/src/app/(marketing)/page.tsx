import { Container, Stack } from "@/components/ui/layout";

/**
 * Public landing page.
 *
 * Rewritten in MC1.2 only to stop hard-coding palette values: it previously used
 * `text-gray-500`, which FRONTEND_SPEC §6 treats as a review reject because it bypasses the
 * design tokens and cannot follow a theme. No product content is added here — the marketing and
 * dashboard surfaces belong to later MC1 slices.
 */
export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center">
      <Container size="sm">
        <Stack gap="sm" className="items-center text-center">
          <h1 className="text-4xl font-bold tracking-tight text-foreground">OmniAI Connect</h1>
          <p className="text-lg text-muted-foreground">Connect Any API. Use It From Any AI.</p>
        </Stack>
      </Container>
    </main>
  );
}
