from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = '38vdr2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()

# Модель для зворотного зв'язку
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)  
    message = db.Column(db.Text, nullable=False)  

    def __repr__(self):
        return f'Зворотній зв\'язок від {self.name} (ID: {self.id})'

# Модель для підписок
class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    plan = db.Column(db.String(50), nullable=False)
    active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'Підписка({self.name}, {self.plan}, {self.active})'

# Створення бази даних, якщо вона не існує
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        feedback = Feedback(name=name, email=email, message=message)

        try:
            db.session.add(feedback)
            db.session.commit()
            return redirect('/')
        except:
            return 'При відправленні повідомлення виникла помилка.'
    else:
        return render_template('feedback.html')

@app.route('/admin')
def admin():
    feedbacks = Feedback.query.all()
    subscriptions = Subscription.query.all()  # Отримання всіх підписок
    return render_template('admin.html', feedbacks=feedbacks, subscriptions=subscriptions)

@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if request.method == 'POST':
        # Отримуємо дані з форми
        name = request.form['name']
        email = request.form['email']
        plan = request.form['plan']

        # Після того як форма відправлена, передаємо ці значення в шаблон для оплати
        return render_template('pay.html', name=name, plan=plan)

    return render_template('subscribe.html')

@app.route('/delete_feedback/<int:id>', methods=['POST'])
def delete_feedback(id):
    feedback = Feedback.query.get_or_404(id)
    db.session.delete(feedback)
    db.session.commit()
    flash('Відгук успішно видалено!', 'success')
    return redirect(url_for('admin'))

@app.route('/cancel_subscription/<int:id>', methods=['POST'])
def cancel_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    subscription.active = False
    db.session.commit()
    flash(f'Підписка на {subscription.plan} була скасована.', 'warning')
    return redirect(url_for('admin'))

@app.route('/pay', methods=['GET', 'POST'])
def pay():
    if request.method == 'POST':
        name = request.form['name']
        plan = request.form['plan']

        return render_template('pay.html', name=name, plan=plan)

    return render_template('pay.html')

# Статична сторінка "Team"
@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    # Отримуємо дані
    name = request.args.get('name')  # Отримуємо через GET
    plan = request.args.get('plan')  # Отримуємо через GET

    # Перевіряємо, чи отримали необхідні параметри
    if not name or not plan:
        flash('Помилка: Відсутні необхідні дані про підписку.', 'danger')
        return redirect(url_for('index'))

    # Реквізити картки
    card_number = request.form['card_number']
    expiry_date = request.form['expiry_date']
    cvv = request.form['cvv']

    # Перевірка валідності реквізитів
    if len(card_number) != 16 or not card_number.isdigit() or len(cvv) != 3:
        flash('Невірно введені реквізити картки!', 'danger')
        return redirect(url_for('pay', name=name, plan=plan))

    # Створюємо запис у базі
    subscription = Subscription(name=name, email=f'{name.lower()}@example.com', plan=plan, active=True)
    try:
        db.session.add(subscription)
        db.session.commit()
        flash('Оплата успішно оброблена, підписка додана!', 'success')
    except Exception as e:
        flash(f'Сталася помилка: {str(e)}', 'danger')
        return redirect(url_for('index'))

    # Перенаправлення
    return redirect(url_for('index'))



@app.route('/login')
def login():
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
