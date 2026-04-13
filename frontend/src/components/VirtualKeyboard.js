import React, { useState } from "react";

const VirtualKeyboard = ({ onChange }) => {
  const [otp, setOtp] = useState("");

  // fixed keypad (no shuffle)
  const numbers = [1,2,3,4,5,6,7,8,9,0];

  const handleClick = (num) => {
    if (otp.length < 6) {
      const newOtp = otp + num;
      setOtp(newOtp);
      onChange(newOtp);
    }
  };

  const handleBackspace = () => {
    const newOtp = otp.slice(0, -1);
    setOtp(newOtp);
    onChange(newOtp);
  };

  const handleClear = () => {
    setOtp("");
    onChange("");
  };

  return (
    <div style={{ textAlign: "center", marginTop: "20px" }}>
      
      {/* OTP Display */}
      <input
        type="password"
        value={otp}
        readOnly
        placeholder="Enter OTP"
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
          color: "#fff"
        }}
      />

      {/* Keypad */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 80px)",
          gap: "15px",
          justifyContent: "center",
        }}
      >
        {numbers.slice(0, 9).map((num) => (
          <button
            key={num}
            onClick={() => handleClick(num)}
            style={buttonStyle}
          >
            {num}
          </button>
        ))}

        <button onClick={handleClear} style={buttonStyle}>C</button>
        <button onClick={() => handleClick(0)} style={buttonStyle}>0</button>
        <button onClick={handleBackspace} style={buttonStyle}>←</button>
      </div>
    </div>
  );
};

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
