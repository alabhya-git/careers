import React from "react";

const DIGITS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

function VirtualKeyboard({ value = "", onChange, maxLength = 6 }) {
  const otp = String(value || "").slice(0, maxLength);

  const handleDigitClick = (digit) => {
    if (otp.length >= maxLength) {
      return;
    }

    onChange(`${otp}${digit}`);
  };

  const handleBackspace = () => {
    onChange(otp.slice(0, -1));
  };

  const handleClear = () => {
    onChange("");
  };

  return (
    <div style={{ textAlign: "center", marginTop: "20px" }}>
      <input
        type="password"
        value={otp}
        readOnly
        placeholder="Enter OTP"
        aria-label="OTP display"
        style={{
          fontSize: "22px",
          textAlign: "center",
          padding: "10px",
          width: "220px",
          borderRadius: "10px",
          border: "1px solid #555",
          marginBottom: "20px",
          letterSpacing: "6px",
          backgroundColor: "#111",
          color: "#fff",
        }}
      />

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 80px)",
          gap: "15px",
          justifyContent: "center",
        }}
      >
        {DIGITS.slice(0, 9).map((digit) => (
          <button
            key={digit}
            type="button"
            onClick={() => handleDigitClick(digit)}
            style={buttonStyle}
          >
            {digit}
          </button>
        ))}

        <button type="button" onClick={handleClear} style={buttonStyle}>
          C
        </button>
        <button type="button" onClick={() => handleDigitClick(0)} style={buttonStyle}>
          0
        </button>
        <button type="button" onClick={handleBackspace} style={buttonStyle}>
          Back
        </button>
      </div>
    </div>
  );
}

const buttonStyle = {
  padding: "15px",
  fontSize: "18px",
  borderRadius: "10px",
  border: "1px solid #555",
  backgroundColor: "#222",
  color: "#fff",
  cursor: "pointer",
};

export default VirtualKeyboard;
