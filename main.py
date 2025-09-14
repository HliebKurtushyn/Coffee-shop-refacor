from datetime import datetime, timedelta
import os
import secrets
import uuid
import logging

import qrcode
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user, LoginManager

from main_db import Basket, Coupons, Menu, Session, SpecialOffer, Users, func, joinedload
from logger_setup import setup_logger

# Чеклист щоб адаптувати сайт під зміни в коді:
# - Замінив nickname -> username: Адаптувати всі шаблони і форми (хто взагалі використовує nickname?)
# - Додати підтримку flash повідомлень в УСІ шаблони
# - Адаптувати всі функції які використовують меню, під використання функції get_menu
# - Перевірити всі форми на наявність CSRF токена
# - Вирізати previous_url звідусіль, де він не потрібен

# - Зробити сторінку оплати як реальну, але без змоги заповнювати дані картки (номер, cvv і т.д.) -> просто кнопка "Оплатити"

# ===== КОНФІГУРАЦІЯ ДОДАТКУ =====
load_dotenv()

app = Flask(__name__)
FILES_PATH = "static/menu"


app_logger = setup_logger("main", "app.log", level_file=logging.INFO, level_console=logging.INFO)


app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["MAX_FORM_MEMORY_SIZE"] = 1024 * 1024
app.config["MAX_FORM_PARTS"] = 500
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ===== СЛУЖБОВІ ФУНКЦІЇ =====
# Штуки які треба зробити перед тим, як юзер побачить сторінку і встигне ЩОСЬ (інколи погане) зробити..
@app.before_request
def do_before_request():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

# Лоадить юзера..
@login_manager.user_loader
def load_user(user_id):
    with Session() as db_session:
        user = db_session.query(Users).filter_by(id=user_id).first()
        if user:
            return user

# Захищаємо від XSS атак
@app.after_request
def apply_csp(response):
    nonce = secrets.token_urlsafe(16)
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    response.set_cookie("nonce", nonce)
    return response

# Робить меню доступною в усіх повсюди, за запитом за цією функцією
@app.context_processor
def utility_processor():
    def get_menu(menu_id):
        with Session() as db_session:
            return db_session.query(Menu).filter_by(id=menu_id).first()
    return dict(get_menu=get_menu)


# ===== ГОЛОВНА СТОРІНКА =====
@app.route("/")
@app.route("/home")
def home():
    # Якщо залогінений
    if current_user.is_authenticated:
        return render_template("home/main.html", user=current_user, 
                          current_year=datetime.now().year)

    # Якщо не залогінений       
    return render_template("home/home.html", user=current_user, 
                          current_year=datetime.now().year)


# ===== АВТЕНТИФІКАЦІЯ =====
# Замінив nickname -> username: Адаптувати всі шаблони і форми
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403
        
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        is_admin = False

        if len(password) < 8:
            flash("Пароль повинен бути довжиною не менше 8 символів!", "danger")
            return render_template("join/register.html",
                                  csrf_token=session["csrf_token"], 
                                  current_year=datetime.now().year)
        
        if email == os.getenv("ADMIN_EMAIL") and username in os.getenv("ADMINS"):
            is_admin = True
        
        with Session() as db_session:
            if (db_session.query(Users).filter_by(email=email).first() or 
                db_session.query(Users).filter_by(username=username).first()):
                flash("Користувач з таким email або юзернеймом вже існує!", "danger")
                return render_template("join/register.html",
                                      csrf_token=session["csrf_token"], 
                                      current_year=datetime.now().year,
)

            new_user = Users(username=username, email=email, is_admin=is_admin)
            new_user.set_password(password)
            db_session.add(new_user)
            db_session.commit()
            db_session.refresh(new_user)
            login_user(new_user)
            return redirect(url_for("home"))
    
    return render_template("join/register.html",
                          csrf_token=session["csrf_token"], 
                          current_year=datetime.now().year)


# @app.post("/register")
# def register_post():

# Замінив nickname -> username: Адаптувати всі шаблони і форми
@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    return render_template("join/login.html",  
                        current_year=datetime.now().year)


@app.post("/login")
def login_post():
    if request.form.get("csrf_token") != session["csrf_token"]:
        return "Request blocked!", 403

    username = request.form["username"]
    password = request.form["password"]

    with Session() as db_session:
        user = db_session.query(Users).filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            session.permanent = True
            return redirect(url_for("home"))

        flash("Неправильний юзернейм або пароль!", "danger")
    
        return redirect(url_for("login"))


@app.get("/profile")
@login_required
def profile():
    return render_template("home/profile.html", user=current_user,
                          current_year=datetime.now().year)


@app.post("/profile")
@login_required
def profile_logout():
    if request.form.get("csrf_token") != session["csrf_token"]:
        return "Request blocked!", 403

    logout_user()
    return redirect(url_for("home"))


# ===== МЕНЮ ТА ПРОДУКТИ =====
@app.route("/menu")
def menu():    
    with Session() as db_session:
        offers = db_session.query(SpecialOffer).options(joinedload(SpecialOffer.menu)).filter_by(active=True).all()
        all_positions = db_session.query(Menu).options(joinedload(Menu.special_offers)).filter_by(active=True).all()

    return render_template("menu/menu.html", all_positions=all_positions, 
                          offers=offers, user=current_user)


@app.route("/position/<name>", methods=["GET", "POST"])
def position(name):
    if request.method == "POST":
        if not current_user.is_authenticated:
            return redirect(url_for("login"))

        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        position_name = request.form.get("name")
        position_quantity = request.form.get("quantity")
        
        if not position_name or not position_quantity:
            return "Invalid data! (Potentially a server side problem)", 400
        
        with Session() as db_session:
            menu_item = db_session.query(Menu).filter_by(name=position_name).first()
            if not menu_item:
                return "Position is not found! (Potentially a server side problem)", 404
            
            total_quantity = db_session.query(func.sum(Basket.quantity)).filter_by(user_id=current_user.id).scalar() or 0

            if total_quantity + int(position_quantity) > 10:
                flash(f"В кошику не може бути більше 10 одиниць товару! Лишня кількість: {total_quantity + int(position_quantity) - 10}", "danger")
                return redirect(url_for("position", name=name))
            
            if db_session.query(Basket).filter_by(user_id=current_user.id).count() > 10:
                flash("В кошику не може бути більше 10 позицій!", "danger")
                return redirect(url_for("position", name=name))

            new_basket_item = Basket(
                user_id=current_user.id,
                menu_id=menu_item.id,
                quantity=int(position_quantity)
            )

            db_session.add(new_basket_item)
            db_session.commit()
            db_session.refresh(new_basket_item)
            flash(f"Додано {new_basket_item.quantity} шт. {new_basket_item.menu.name} до кошика", "success")
    
    with Session() as db_session:
        position = db_session.query(Menu).options(joinedload(Menu.special_offers)).filter_by(active=True, name=name).first()
        return render_template("menu/position.html", 
                              csrf_token=session["csrf_token"], 
                              position=position)
    

# ===== КОШИК ТА ЗАМОВЛЕННЯ =====
@app.route("/basket", methods=["GET", "POST"])
@login_required
def basket():
    with Session() as db_session:
        basket_items = db_session.query(Basket).filter_by(user_id=current_user.id).options(joinedload(Basket.menu)).all()

        if request.method == "POST":
            if request.form.get("csrf_token") != session["csrf_token"]:
                return "Request blocked!", 403

            for item in basket_items:
                session[item]["quantity"] = request.form.get(f"quantity_{item.id}", item.quantity)
                item.quantity = int(session[item]["quantity"])

            item_id = request.form.get("item_id")

            if not item_id:
                return "Некоректні дані!", 400

            basket_item = db_session.query(Basket).filter_by(id=item_id, user_id=current_user.id).first()
            if not basket_item:
                return "Елемент кошика не знайдено!", 404

            db_session.delete(basket_item)
            db_session.commit()
            flash(f"Видалено {basket_item.menu.name} з кошика", "success")

        return render_template("orders/basket.html",
                                csrf_token=session["csrf_token"],
                                basket=basket_items, user=current_user)
    

@app.route("/update_quantity", methods=["POST"])
@login_required
def update_quantity():
    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403
        
        item_id = request.form.get("item_id")
        quantity = request.form.get("quantity")

        with Session() as db_session:
            basket_item = db_session.query(Basket).filter_by(id=item_id, user_id=current_user.id).first()
            if not basket_item:
                return "Елемент кошика не знайдено!", 404

            # Підрахунок загальної кількості, враховуючи нову кількість для цього товару
            other_items_quantity = db_session.query(func.sum(Basket.quantity)).filter(Basket.user_id == current_user.id, Basket.id != basket_item.id).scalar() or 0
            new_total_quantity = other_items_quantity + int(quantity)

            if new_total_quantity > 10:
                flash(f"В кошику не може бути більше 10 одиниць товару! Лишня кількість: {new_total_quantity - 10}", "danger")
                return redirect(url_for("basket"))
            
            if quantity and quantity.isdigit() and int(quantity) > 0:
                basket_item.quantity = int(quantity)
                db_session.commit()
    
    return redirect(url_for("basket"))


@app.route("/remove_from_basket", methods=["POST"])
@login_required
def remove_from_basket():
    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403
        
        item_id = request.form.get("item_id")

        with Session() as db_session:
            basket_item = db_session.query(Basket).filter_by(id=item_id, user_id=current_user.id).first()

            if not basket_item:
                return "Елемент кошика не знайдено!", 404
            
            db_session.delete(basket_item)
            db_session.commit()

            return redirect(url_for("basket"))
        

# Прибрав post метод, бо він не потрібен тут. Перевірити чи точно він не використовується в шаблоні
@app.route("/checkout_page", methods=["GET"]) # (тут був 'POST')
@login_required
def checkout_page():    
    with Session() as db_session:
        basket = db_session.query(Basket).filter_by(user_id=current_user.id).all()

        return render_template("orders/checkout_page.html", 
                            csrf_token=session["csrf_token"], 
                            basket=basket,
                            total_quantity=sum(item.quantity for item in basket),
                            total_price=sum(item.menu.price for item in basket))


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    with Session() as db_session:
        if request.method == "POST":
            if request.form.get("csrf_token") != session["csrf_token"]:
                return "Request blocked!", 403

            basket_items = db_session.query(Basket).filter_by(user_id=current_user.id).options(joinedload(Basket.menu)).all()
            
            if not basket_items:
                flash("Ваш кошик порожній", "danger")
                return redirect(url_for("basket"))
            
            else:
                order_items = {}
                total_price = 0

                for item in basket_items:
                    price = item.menu.price
                    if item.menu.special_offers:
                        active_offer = next(
                            (offer for offer in item.menu.special_offers
                             if offer.active and offer.expiration_date > datetime.now()),
                            None
                        )
                        if active_offer:
                            price = round(price - (price * active_offer.discount / 100), 2)
                    order_items[item.menu.id] = item.quantity
                    total_price += price * item.quantity

                new_coupon = Coupons(
                    order_items=order_items,
                    order_time=datetime.now(),
                    user_id=current_user.id
                )

                db_session.add(new_coupon)
                db_session.commit()
                db_session.refresh(new_coupon)

                qr_data = f"ORDER:{new_coupon.id}"
                qr_img = qrcode.make(qr_data)
                qr_filename = f"coupon_{new_coupon.id}.png"
                qr_path = os.path.join("static/qrcodes", qr_filename)
                qr_img.save(qr_path)

                new_coupon.qr_code_path = qr_path
                db_session.commit()

                db_session.query(Basket).filter_by(user_id=current_user.id).delete()
                db_session.commit()
                
                flash(f"Замовлення оформлено! Загальна сума: {total_price}₴", "success")
                return redirect(url_for("my_coupons"))


@app.route("/my_coupons")
@login_required
def my_coupons():
    with Session() as db_session:
        coupons = db_session.query(Coupons).filter_by(user_id=current_user.id).all()
    
        return render_template("orders/my_coupons.html", coupons=coupons, user=current_user)
    

@app.route("/coupon/<int:coupon_id>")
@login_required
def coupon(coupon_id):
    previous_url = session.get("previous_url") or url_for("my_coupons")
    
    with Session() as db_session:
        order = db_session.query(Coupons).filter_by(id=coupon_id, user_id=current_user.id).first()
        if not order:
            return "Купон не знайдено!", 404

        return render_template("orders/coupon.html", order=order,
                            previous_url=previous_url, user=current_user)
    

# ===== АДМІНІСТРУВАННЯ =====
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return "Шо, адміном себе представляєш?", 418

    previous_url = session.get("previous_url") or url_for("home")
    
    with Session() as db_session:
        users = db_session.query(Users).all()
    return render_template("admin/admin.html", users=users,
                         previous_url=previous_url)


@app.route("/add_position", methods=["GET", "POST"])
@login_required
def add_position():
    if not current_user.is_admin:
        return "Access denied!", 403

    previous_url = session.get("previous_url") or url_for("admin")

    if request.method == "POST":
        if request.form.get("csrf_token") != session["csrf_token"]:
            return "Request blocked!", 403

        name = request.form["name"]
        file = request.files.get("img")
        ingredients = request.form["ingredients"]
        description = request.form["description"]
        price = request.form["price"]
        weight = request.form["weight"]

        if not file or not file.filename:
            return "Файл не вибрано або завантаження не вдалося"

        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        output_path = os.path.join("static/menu", unique_filename)

        with open(output_path, "wb") as f:
            f.write(file.read())

        with Session() as db_session:
            new_position = Menu(name=name, ingredients=ingredients, 
                               description=description, price=price, 
                               weight=weight, file_name=unique_filename)
            db_session.add(new_position)
            db_session.commit()

        flash("Позицію додано успішно!", "success")

    return render_template("admin/add_position.html", csrf_token=session["csrf_token"],
                         previous_url=previous_url)


@app.route("/add_offer", methods=["GET", "POST"])
@login_required
def add_offer():
    if not current_user.is_admin:
        return "Access denied!", 403

    previous_url = session.get("previous_url") or url_for("admin")

    with Session() as db_session:
        all_positions = db_session.query(Menu).filter_by(active=True).all()

        if request.method == "POST":
            if request.form.get("csrf_token") != session["csrf_token"]:
                return "Request blocked!", 403 

            menu_id = request.form["menu_id"]
            discount = float(request.form["discount"])
            expiration_date = datetime.fromisoformat(request.form["expiration_date"])
            active = "active" in request.form

            new_position = SpecialOffer(
                menu_id=menu_id, 
                discount=discount, 
                expiration_date=expiration_date, 
                active=active
            )
            db_session.add(new_position)
            db_session.commit()
            flash("Пропозицію додано успішно!", "success")

    with Session() as db_session:
        all_positions = db_session.query(Menu).filter_by(active=True).all()
        
        return render_template(
            "admin/add_offer.html", 
            csrf_token=session["csrf_token"], 
            all_positions=all_positions,
            previous_url=previous_url
        )


# ===== ЗАПУСК ЗАСТОСУНКУ =====
if __name__ == "__main__":
    with Session() as db_session:
        SpecialOffer.deactivate_expired(db_session)
    app.run(debug=True)