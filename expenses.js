// Sample expense data (replace with real database later)
let expenses = [];

document.getElementById('expense-form')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const form = e.target;
  const newExpense = {
    amount: form[0].value,
    category: form[1].value,
    date: form[2].value
  };
  expenses.push(newExpense);
  updateExpenseList();
  form.reset();
});

function updateExpenseList() {
  const table = document.getElementById('expense-table')?.querySelector('tbody');
  if (table) {
    table.innerHTML = expenses.map(expense => `
      <tr>
        <td>${expense.date}</td>
        <td>${expense.category}</td>
        <td>$${expense.amount}</td>
      </tr>
    `).join('');
  }
}