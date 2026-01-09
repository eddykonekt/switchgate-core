type Adapter = {
  validatePin: (msisdn: string, pin: string) => Promise<boolean>;
  verifyOtp: (msisdn: string, otp: string) => Promise<boolean>;
};

const mtnNg: Adapter = {
  async validatePin(msisdn, pin) {
    // call MTN API; return boolean
    return pin.length >= 4;
  },
  async verifyOtp(msisdn, otp) {
    // call MTN OTP API; return boolean
    return otp.length === 6;
  },
};

const airtelNg: Adapter = {
  async validatePin(msisdn, pin) { return pin.length >= 4; },
  async verifyOtp(msisdn, otp) { return otp.length === 6; },
};

export const adapters = new Map<string, Adapter>([
  ['MTN-NG', mtnNg],
  ['AIRTEL-NG', airtelNg],
]);