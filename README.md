Моделі даних
Feedback: Представляє записи зворотного зв'язку від користувачів.
Subscription: Зберігає інформацію про підписки користувачів.
Функції та їхнє призначення
index, about, team: Рендерують відповідні сторінки (головна, про нас, команда).
feedback: Обробляє форму зворотного зв'язку, зберігає дані в базі та перенаправляє користувача на головну сторінку.
admin: Відображає список всіх зворотних зв'язків та підписок для адміністратора.
subscribe: Обробляє форму підписки, перенаправляє на сторінку оплати.
delete_feedback: Видаляє запис зворотного зв'язку.
cancel_subscription: Скасовує підписку.
pay: Обробляє форму оплати, перевіряє дані картки та зберігає інформацію про підписку в базі.
process_payment: Симулює обробку платежу (в реальному додатку тут би була інтеграція з платіжною системою).
login: Рендерує сторінку входу (не реалізована функціональність авторизації).
Детальніше про функції
feedback:
Отримує дані з форми (ім'я, email, повідомлення).
Створює об'єкт моделі Feedback.
Зберігає об'єкт в базу даних.
При успішному збереженні перенаправляє на головну сторінку.
admin:
Запитує всі записи з таблиць Feedback та Subscription.
Передає отримані дані в шаблон для відображення.
subscribe:
Обробляє форму підписки, отримує дані про користувача та план.
Перенаправляє на сторінку оплати, передаючи необхідні дані.
pay:
Отримує дані з форми оплати (номер картки, термін дії, CVV).
Перевіряє валідність даних.
Створює запис про підписку в базі даних.
Симулює обробку платежу.
process_payment:
Отримує дані про підписку з URL-параметрів та форми.
Перевіряє наявність всіх необхідних даних.
Перевіряє валідність даних картки.
Створює запис про підписку в базі даних.
Перенаправляє користувача на головну сторінку з відповідним повідомленням.
