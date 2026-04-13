import React, { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import VirtualKeyboard from "./VirtualKeyboard";

function KeyboardInForm({ onSubmit = () => {} }) {
  const [value, setValue] = useState("");

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <VirtualKeyboard value={value} onChange={setValue} />
      <button type="submit">Submit</button>
      <button type="button" onClick={() => setValue("")}>
        Reset
      </button>
    </form>
  );
}

test("virtual keyboard buttons do not submit the surrounding form", async () => {
  const submitSpy = jest.fn();

  render(<KeyboardInForm onSubmit={submitSpy} />);

  await userEvent.click(screen.getByRole("button", { name: "1" }));
  await userEvent.click(screen.getByRole("button", { name: "2" }));
  await userEvent.click(screen.getByRole("button", { name: "3" }));

  expect(screen.getByLabelText(/otp display/i)).toHaveValue("123");
  expect(submitSpy).not.toHaveBeenCalled();
});

test("virtual keyboard respects parent-controlled value changes", async () => {
  render(<KeyboardInForm />);

  await userEvent.click(screen.getByRole("button", { name: "1" }));
  await userEvent.click(screen.getByRole("button", { name: "2" }));
  await userEvent.click(screen.getByRole("button", { name: "Back" }));

  expect(screen.getByLabelText(/otp display/i)).toHaveValue("1");

  await userEvent.click(screen.getByRole("button", { name: "Reset" }));
  expect(screen.getByLabelText(/otp display/i)).toHaveValue("");
});
