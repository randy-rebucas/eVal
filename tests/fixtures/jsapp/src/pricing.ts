export interface Price {
  amount: number;
  currency: string;
}

export function applyDiscount(price: Price, percent: number): Price {
  const amount: number = price.amount * (1 - percent / 100);
  return { amount, currency: price.currency };
}

export const total: number = applyDiscount({ amount: 10, currency: "EUR" }, "15").amount;
