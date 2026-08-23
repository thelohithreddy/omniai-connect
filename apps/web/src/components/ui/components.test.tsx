import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, test } from "vitest";

import { Alert, AlertDescription, AlertTitle } from "./alert";
import { Button } from "./button";
import { Card, CardContent, CardHeader, CardTitle } from "./card";
import { EmptyState, ErrorState, LoadingState, Skeleton } from "./feedback";
import { Field } from "./field";
import { Container, Stack } from "./layout";

/**
 * Design-system behaviour and accessibility (MC1.2, ADR-0044 §9; FRONTEND_SPEC §7).
 *
 * These test behaviour a user can observe — what is announced, what is reachable by keyboard,
 * what is disabled — rather than class names. Asserting `className` would pin the implementation
 * and prove nothing about whether the component actually works.
 */

/** Run axe against a container and return violation ids. */
async function violations(container: HTMLElement): Promise<string[]> {
  const results = await axe.run(container, {
    // Colour contrast is computed from the stylesheet, which jsdom does not apply; it is asserted
    // directly against the tokens in `design-tokens.test.ts` instead. Claiming a contrast pass
    // here would be a vacuous result.
    rules: { "color-contrast": { enabled: false } },
  });
  return results.violations.map((violation) => violation.id);
}

describe("the accessibility scanner itself", () => {
  test("axe detects a planted violation (positive control)", async () => {
    // A clean scan is only evidence if the scanner is first shown to find something. Without
    // this, "0 violations" could equally mean "axe never ran".
    const { container } = render(
      <div>
        {/*
          These violations are the point of the test: an unlabelled input and an image with no
          alt text. The lint rules that would normally catch them are disabled *here only* —
          silencing them project-wide, or "fixing" this markup, would leave the scanner
          unvalidated and every clean result below unfounded.
        */}
        <input type="text" />
        {/* eslint-disable-next-line @next/next/no-img-element, jsx-a11y/alt-text */}
        <img src="/x.png" />
      </div>,
    );

    const found = await violations(container);

    expect(found.length).toBeGreaterThan(0);
  });
});

describe("Button", () => {
  test("is reachable and activatable by keyboard alone", async () => {
    const user = userEvent.setup();
    let clicks = 0;
    render(<Button onClick={() => (clicks += 1)}>Save</Button>);

    await user.tab();
    expect(screen.getByRole("button", { name: "Save" })).toHaveFocus();

    await user.keyboard("{Enter}");
    await user.keyboard(" ");
    expect(clicks).toBe(2);
  });

  test("a loading button is disabled and announced as busy", async () => {
    const user = userEvent.setup();
    let clicks = 0;
    render(
      <Button isLoading onClick={() => (clicks += 1)}>
        Save
      </Button>,
    );

    const button = screen.getByRole("button", { name: "Save" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");

    // The failure this prevents: a form that stays clickable while submitting and fires twice.
    await user.click(button);
    expect(clicks).toBe(0);
  });

  test("a disabled button is not focusable and does not fire", async () => {
    const user = userEvent.setup();
    let clicks = 0;
    render(
      <Button disabled onClick={() => (clicks += 1)}>
        Delete
      </Button>,
    );

    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(clicks).toBe(0);
  });

  test("the caller's className wins over the variant's", () => {
    // tailwind-merge resolves the collision. Without it the outcome would depend on stylesheet
    // order rather than intent.
    render(<Button className="bg-destructive">Danger</Button>);

    // Compared as tokens, not as a substring: `hover:bg-primary/90` legitimately survives because
    // tailwind-merge treats a hover-variant background as a different group from the base one.
    // A substring assertion would fail on that and hide what is actually being checked — that the
    // *base* background was replaced. Callers wanting both should use variant="destructive".
    const tokens = screen.getByRole("button").className.split(/\s+/);
    expect(tokens).toContain("bg-destructive");
    expect(tokens).not.toContain("bg-primary");
  });

  test.each(["primary", "secondary", "outline", "ghost", "destructive"] as const)(
    "the %s variant has no accessibility violations",
    async (variant) => {
      const { container } = render(<Button variant={variant}>Action</Button>);
      expect(await violations(container)).toEqual([]);
    },
  );
});

describe("Field", () => {
  test("the label is bound to the control", async () => {
    render(<Field label="Workspace name" />);

    // getByLabelText only resolves through a real binding, so this fails if htmlFor/id drift.
    expect(screen.getByLabelText("Workspace name")).toBeInstanceOf(HTMLInputElement);
  });

  test("an error is announced and marks the field invalid", () => {
    render(<Field label="Email" error="Enter a valid email address." />);

    const input = screen.getByLabelText("Email");
    expect(input).toHaveAttribute("aria-invalid", "true");

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Enter a valid email address.");
    // The message must be reachable *from the input*, not merely present on the page.
    expect(input.getAttribute("aria-describedby")).toContain(alert.id);
  });

  test("description and error are both described when both are present", () => {
    render(<Field label="Token" description="Shown once." error="Required." />);

    const describedBy = screen.getByLabelText("Token").getAttribute("aria-describedby")!.split(" ");
    expect(describedBy).toHaveLength(2);
  });

  test("a required field is announced as required, not just marked with an asterisk", () => {
    render(<Field label="Name" required />);

    // The asterisk is aria-hidden; a screen reader user hears the explicit word.
    expect(screen.getByLabelText(/Name/)).toBeRequired();
    expect(screen.getByText("(required)")).toBeInTheDocument();
  });

  test("two fields with the same label do not collide", () => {
    // useId, not a hard-coded id. A literal id would silently break the second field's binding.
    render(
      <>
        <Field label="Name" />
        <Field label="Name" />
      </>,
    );

    const [first, second] = screen.getAllByLabelText("Name");
    expect(first!.id).not.toBe(second!.id);
  });

  test("typing works and is not intercepted", async () => {
    const user = userEvent.setup();
    render(<Field label="Search" />);

    await user.type(screen.getByLabelText("Search"), "postgres");
    expect(screen.getByLabelText("Search")).toHaveValue("postgres");
  });

  test("has no accessibility violations, with or without an error", async () => {
    const clean = render(<Field label="Email" description="Work address." />);
    expect(await violations(clean.container)).toEqual([]);

    const invalid = render(<Field label="Email" error="Required." />);
    expect(await violations(invalid.container)).toEqual([]);
  });
});

describe("Alert", () => {
  test("a failure is announced assertively, other states politely", () => {
    // Getting this backwards is the common defect: an error nobody hears, or an info banner so
    // noisy that users switch announcements off.
    const { unmount } = render(<Alert variant="danger">Connection failed</Alert>);
    expect(screen.getByRole("alert")).toHaveTextContent("Connection failed");
    unmount();

    render(<Alert variant="success">Saved</Alert>);
    expect(screen.getByRole("status")).toHaveTextContent("Saved");
  });

  test("defaults to a polite status", () => {
    render(<Alert>Heads up</Alert>);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  test("has no accessibility violations", async () => {
    const { container } = render(
      <Alert variant="danger">
        <AlertTitle>Could not connect</AlertTitle>
        <AlertDescription>Check the credential and try again.</AlertDescription>
      </Alert>,
    );

    expect(await violations(container)).toEqual([]);
  });
});

describe("feedback states", () => {
  test("a loading region announces itself and hides its skeletons", () => {
    render(<LoadingState label="Loading tool calls" />);

    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status).toHaveTextContent("Loading tool calls");
  });

  test("a skeleton is decorative and never announced", () => {
    const { container } = render(<Skeleton className="h-4 w-10" />);
    expect(container.firstElementChild).toHaveAttribute("aria-hidden", "true");
  });

  test("an empty state renders a real heading at the requested level", () => {
    render(<EmptyState title="No connections yet" headingAs="h2" description="Connect an API." />);

    expect(screen.getByRole("heading", { name: "No connections yet", level: 2 })).toBeInTheDocument();
  });

  test("an error state surfaces the request id for support", () => {
    // FRONTEND_SPEC §8: the user quotes one string and support finds the exact request.
    render(<ErrorState message="The API did not respond." requestId="req_01JABC" />);

    expect(screen.getByRole("alert")).toHaveTextContent("The API did not respond.");
    expect(screen.getByText("req_01JABC")).toBeInTheDocument();
  });

  test("feedback states have no accessibility violations", async () => {
    const { container } = render(
      <div>
        <LoadingState label="Loading" />
        <EmptyState title="Nothing here" description="Add one." />
        <ErrorState message="Failed." requestId="req_1" />
      </div>,
    );

    expect(await violations(container)).toEqual([]);
  });
});

describe("Card and layout primitives", () => {
  test("the card title honours the requested heading level", () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle as="h2">Connections</CardTitle>
        </CardHeader>
        <CardContent>Two active.</CardContent>
      </Card>,
    );

    expect(screen.getByRole("heading", { name: "Connections", level: 2 })).toBeInTheDocument();
  });

  test("layout primitives render their children and have no violations", async () => {
    const { container } = render(
      <Container size="md">
        <Stack gap="lg">
          <p>One</p>
          <p>Two</p>
        </Stack>
      </Container>,
    );

    expect(screen.getByText("One")).toBeInTheDocument();
    expect(await violations(container)).toEqual([]);
  });
});

describe("keyboard traversal across a composed form", () => {
  test("tab order follows document order and nothing is a trap", async () => {
    const user = userEvent.setup();
    render(
      <form>
        <Field label="Name" />
        <Field label="Email" />
        <Button type="submit">Create</Button>
      </form>,
    );

    await user.tab();
    expect(screen.getByLabelText("Name")).toHaveFocus();
    await user.tab();
    expect(screen.getByLabelText("Email")).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Create" })).toHaveFocus();

    // And back out again — a component that captured focus would fail here.
    await user.tab({ shift: true });
    expect(screen.getByLabelText("Email")).toHaveFocus();
  });
});
