from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
from werkzeug.exceptions import HTTPException

# Ініціалізація додатка Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = '38vdr2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = '38vdr2024' 
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.app_context().push()

# Модель для користувача
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'User({self.email})'

# Модель для API (Items)
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)

# Моделі для відгуків та підписок
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'Зворотній зв\'язок від {self.name} (ID: {self.id})'

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

# Глобальна обробка помилок
@app.errorhandler(Exception)
def handle_exception(error):
    if isinstance(error, HTTPException):
        return jsonify({"error": error.description}), error.code
    else:
        # Додаємо логування для відстеження помилок
        app.logger.error(f"Unhandled exception: {error}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "details": str(error)}), 500

# Спеціальна обробка 404 помилок
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

# --- API для Feedback ---
@app.route('/api/feedbacks', methods=['GET'])
def get_feedbacks():
    feedbacks = Feedback.query.all()
    return jsonify([
        {'id': fb.id, 'name': fb.name, 'email': fb.email, 'message': fb.message}
        for fb in feedbacks
    ])

@app.route('/api/feedbacks', methods=['POST'])
def add_feedback():
    data = request.json
    if not all(k in data for k in ('name', 'email', 'message')):
        return jsonify({"error": "Invalid data"}), 400
    feedback = Feedback(name=data['name'], email=data['email'], message=data['message'])
    db.session.add(feedback)
    db.session.commit()
    return jsonify({"message": "Feedback added!", "feedback": {
        'id': feedback.id, 'name': feedback.name, 'email': feedback.email, 'message': feedback.message
    }}), 201

@app.route('/api/feedbacks/<int:id>', methods=['DELETE'])
def delete_feedback_api(id):
    feedback = Feedback.query.get_or_404(id)
    db.session.delete(feedback)
    db.session.commit()
    return jsonify({"message": f"Feedback with ID {id} deleted."})

# --- API для Subscription ---
@app.route('/api/subscriptions', methods=['GET'])
def get_subscriptions():
    subscriptions = Subscription.query.all()
    return jsonify([
        {'id': sub.id, 'name': sub.name, 'email': sub.email, 'plan': sub.plan, 'active': sub.active}
        for sub in subscriptions
    ])

@app.route('/api/subscriptions', methods=['POST'])
def add_subscription():
    data = request.json
    if not all(k in data for k in ('name', 'email', 'plan')):
        return jsonify({"error": "Invalid data"}), 400
    subscription = Subscription(
        name=data['name'], email=data['email'], plan=data['plan'], active=data.get('active', True)
    )
    db.session.add(subscription)
    db.session.commit()
    return jsonify({"message": "Subscription added!", "subscription": {
        'id': subscription.id, 'name': subscription.name, 'email': subscription.email, 'plan': subscription.plan,
        'active': subscription.active
    }}), 201

@app.route('/api/subscriptions/<int:id>', methods=['PUT'])
def update_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    data = request.json
    subscription.plan = data.get('plan', subscription.plan)
    subscription.active = data.get('active', subscription.active)
    db.session.commit()
    return jsonify({"message": f"Subscription with ID {id} updated.", "subscription": {
        'id': subscription.id, 'name': subscription.name, 'email': subscription.email, 'plan': subscription.plan,
        'active': subscription.active
    }})

@app.route('/api/subscriptions/<int:id>', methods=['DELETE'])
def delete_subscription(id):
    subscription = Subscription.query.get_or_404(id)
    db.session.delete(subscription)
    db.session.commit()
    return jsonify({"message": f"Subscription with ID {id} deleted."})

# --- API для Users ---
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')

    # Перевірка на порожні поля
    if not all([name, email, password, confirm_password]):
        return jsonify({"error": "Missing required fields"}), 400

    if password != confirm_password:
        return jsonify({"error": "Паролі не співпадають!"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Користувач з таким email вже зареєстрований!"}), 400

    try:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Реєстрація успішна!"}), 201
    except Exception as e:
        return jsonify({"error": f"Помилка при реєстрації: {str(e)}"}), 500

@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.json

    # Перевірка наявності необхідних полів
    if not all(k in data for k in ('email', 'password')):
        return jsonify({"error": "Invalid data, both email and password are required"}), 400

    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'id': user.id, 'email': user.email})
        return jsonify({"message": "Login successful!", "access_token": access_token})

    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def profile_api():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    subscriptions = Subscription.query.filter_by(email=user.email).all()
    return jsonify({
        "user": {'id': user.id, 'name': user.name, 'email': user.email},
        "subscriptions": [
            {'id': sub.id, 'plan': sub.plan, 'active': sub.active} for sub in subscriptions
        ]
    })

@app.route('/api/logout', methods=['GET'])
def logout_api():
    session.pop('user_id', None)
    return jsonify({"message": "Logged out."})

# --- API для оплати ---
@app.route('/api/process_payment', methods=['POST'])
def process_payment_api():
    data = request.json

    # Перевірка наявності необхідних полів
    if not all(k in data for k in ('card_number', 'expiry_date', 'cvv', 'plan')):
        return jsonify({"error": "Invalid data, all fields are required"}), 400

    # Перевірка правильності карткових даних
    if len(data['card_number']) != 16 or not data['card_number'].isdigit() or len(data['cvv']) != 3:
        return jsonify({"error": "Invalid card details"}), 400

    # Логіка для додавання підписки (можна додати перевірки на існуючі підписки або інші умови)
    subscription = Subscription(
        name="Anonymous", email="anon@example.com", plan=data['plan'], active=True
    )
    try:
        db.session.add(subscription)
        db.session.commit()
        return jsonify({"message": "Payment processed, subscription added!", "subscription": {
            'id': subscription.id, 'plan': subscription.plan, 'active': subscription.active
        }}), 201
    except Exception as e:
        return jsonify({"error": f"Payment processing error: {str(e)}"}), 500

# --- Інші маршрути ---
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
    subscriptions = Subscription.query.all()
    return render_template('admin.html', feedbacks=feedbacks, subscriptions=subscriptions)

@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if 'user_id' not in session:
        flash('Будь ласка, увійдіть у систему, щоб оформити підписку.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        plan = request.form['plan']

        # Перенаправлення на сторінку оплати
        return redirect(url_for('pay', name=name, plan=plan))

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

    # Перевіряємо, чи запит надійшов з профілю або адмін-панелі
    if 'user_id' in session:
        return redirect(url_for('profile'))  # якщо це профіль користувача
    else:
        return redirect(url_for('admin'))  # якщо це адмін-панель

@app.route('/pay', methods=['GET', 'POST'])
def pay():
    # Отримання параметрів із запиту
    name = request.args.get('name')
    plan = request.args.get('plan')

    if not name or not plan:
        flash('Помилка: Відсутні необхідні дані про підписку.', 'danger')
        return redirect(url_for('subscribe'))

    if request.method == 'POST':
        # Логіка обробки платіжної інформації
        card_number = request.form['card_number']
        expiry_date = request.form['expiry_date']
        cvv = request.form['cvv']

        if len(card_number) != 16 or not card_number.isdigit() or len(cvv) != 3:
            flash('Невірно введені реквізити картки!', 'danger')
            return redirect(url_for('pay', name=name, plan=plan))

        # Додавання підписки
        user = db.session.get(User, session['user_id'])
        if not user:
            flash('Користувача не знайдено.', 'danger')
            return redirect(url_for('login'))

        subscription = Subscription(name=name, email=user.email, plan=plan, active=True)
        db.session.add(subscription)
        db.session.commit()

        flash('Оплата успішно оброблена, підписка додана!', 'success')
        return redirect(url_for('profile'))

    return render_template('pay.html', name=name, plan=plan)

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    if 'user_id' not in session:  # Перевіряємо, чи користувач увійшов у систему
        flash('Будь ласка, увійдіть у систему для оформлення підписки.', 'warning')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])  # Отримуємо поточного користувача
    
    if not user:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('index'))

    # Збираємо дані для підписки
    name = user.name  # Ім'я з профілю
    email = user.email  # Email з профілю
    plan = request.form['plan']  # План підписки з форми

    # Перевіряємо реквізити картки
    card_number = request.form['card_number']
    expiry_date = request.form['expiry_date']
    cvv = request.form['cvv']
    if len(card_number) != 16 or not card_number.isdigit() or len(cvv) != 3:
        flash('Невірно введені реквізити картки!', 'danger')
        return redirect(url_for('pay'))

    # Створюємо нову підписку
    subscription = Subscription(
        name=name,
        email=email,
        plan=plan,
        active=True
    )

    try:
        # Зберігаємо підписку в базу даних
        db.session.add(subscription)
        db.session.commit()
        flash('Оплата успішно оброблена, підписка додана!', 'success')
    except Exception as e:
        flash(f'Сталася помилка при збереженні підписки: {str(e)}', 'danger')
        return redirect(url_for('index'))

    return redirect(url_for('profile'))  # Повертаємося на сторінку профілю


# --- Реєстрація користувача ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        # Перевірка, чи паролі співпадають
        if password != confirm_password:
            flash('Паролі не співпадають!', 'danger')
            return redirect(url_for('register'))

        # Перевірка, чи користувач з таким email вже існує
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Користувач з таким email вже зареєстрований!', 'danger')
            return redirect(url_for('register'))

        # Створення нового користувача
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password)

        # Додавання користувача в базу даних
        db.session.add(new_user)
        db.session.commit()

        flash('Реєстрація успішна! Ви можете увійти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# --- Авторизація користувача (Login) ---
# Маршрут для логіну
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Ви успішно увійшли!', 'success')
            return redirect(url_for('profile'))

        flash('Невірний email або пароль', 'danger')

    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Будь ласка, увійдіть у систему.', 'warning')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])  # Поточний користувач
    if not user:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('login'))

    # Отримуємо підписки користувача
    subscriptions = Subscription.query.filter_by(email=user.email).all()

    return render_template('profile.html', user=user, subscriptions=subscriptions)

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Видаляємо користувача з сесії
    flash('Ви успішно вийшли!', 'success')
    return redirect(url_for('index'))

# --- Захищений маршрут, що вимагає авторизації ---
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)
