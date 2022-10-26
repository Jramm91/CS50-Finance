import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # get user's id in variable
    user_id = session["user_id"]

    # grab the information from the transactions table
    # TODO make a new table of "holdings" to keep track of current portfolio and update stock prices in real time to
    # accurately reflect on the main page
    holdings_db = db.execute(
        "SELECT * FROM holdings WHERE user_id = ?", user_id
    )

    # update prices in holdings table
    for holding in holdings_db:
        symbol = holding["symbol"]
        price = lookup(symbol)["price"]
        total = holding["shares"] * price
        db.execute("UPDATE holdings SET curr_price = ?, total = ? WHERE symbol = ? AND user_id = ?", price, total, symbol, user_id)

    transactions_db = db.execute(
        "SELECT symbol, SUM(shares) AS shares, price, company_name FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)

    # get the user's current cash amount
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

    # get real value of cash from cash_db
    cash = cash_db[0]["cash"]

    return render_template("index.html", holdings=holdings_db, cash=usd(cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # get inputs from form and store in values
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares", type=int)

        # make sure symbol field is filled out
        if not symbol:
            return apology("please enter a stock symbol", 400)

        # use lookup function to find the entered stock symbol
        stock = lookup(symbol.upper())

        # make sure symbol entered is real
        if stock == None:
            return apology("stock symbol does not exist", 400)

        # make sure number entered in shares field is a positive int
        if not shares:
            return apology("please enter a number", 400)

        try:
            shares_form = int(request.form.get("shares"))
        except:
            return apology("invalid entry", 400)

        if shares < 0:
            return apology("enter a positive number", 400)

        # calculate transaction amount
        tranax_amnt = shares * stock["price"]

        # get the current user id from the session
        user_id = session["user_id"]

        # get the current user's cash amount from the users table in the db
        user_cash_amnt = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)

        # store the users actual cash value as a variable from the dictionary created in the line above: [ith element in dictionary = 0]['cash' amount]
        user_acnt_bal = user_cash_amnt[0]["cash"]

        # check if user has enough money to buy
        if user_acnt_bal < tranax_amnt:
            return apology("insufficient funds", 400)

        uptd_acnt_bal = user_acnt_bal - tranax_amnt

        # update users current account ballance
        db.execute("UPDATE users SET cash = ? WHERE id = ?", uptd_acnt_bal, user_id)

        # make varialbe to capture current date to use in the next step
        date = datetime.datetime.today()

        # fill in new transaction into database
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_amount, date, company_name) VALUES (?, ?, ?, ?, ?,?, ?)",
         user_id, stock["symbol"], shares, stock["price"], tranax_amnt, date, stock["name"])

        name = stock["name"]
        curr_price = stock["price"]
        # check if user owns stock already
        rows = db.execute("SELECT * FROM holdings WHERE user_id = :id AND symbol = :symbol", id=user_id, symbol=symbol)
        if len(rows) != 0:
            curr_shares = int(rows[0]["shares"])
            new_shares = int(shares) + curr_shares
            price = lookup(symbol)["price"]
            total = price * new_shares
            db.execute("UPDATE holdings SET shares = :shares, curr_price = :price, total = :total WHERE user_id = :id AND symbol = :symbol",
                        shares=new_shares, price=price, total=total, id=user_id, symbol=symbol)
        else:
            db.execute("INSERT INTO holdings (user_id, symbol, company_name, shares, curr_price, total, cash) VALUES (:user_id, :symbol, :name, :shares, :price, :total, :cash)",
                        user_id=user_id, symbol=symbol, name=name, shares=shares, price=curr_price, total=tranax_amnt, cash=uptd_acnt_bal)

        # create a flash message to tell user what was purchased and for how much
        message = f"Successfully purchased {stock['symbol']} for {usd(tranax_amnt)}"
        flash(message)
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions_db = db.execute(
        "SELECT symbol, company_name, shares, price, transaction_amount, date FROM transactions WHERE user_id =:id", id=user_id)

    return render_template("history.html", transactions=transactions_db)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        # Store user input for stock symbols
        symbol = request.form.get("symbol")

        # Check if user entered a stock symbol
        if not symbol:
            return apology("please give a stock symbol", 400)

        # use the function lookup from helpers.py to get current price of stock
        quote = lookup(symbol.upper())

        # Check if stock symbol exists
        if quote == None:
            return apology("stock symbol does not exist", 400)
        # take user to page that displays the name of the company, current stock price and company's stock symbol
        # values from lookup function in helpers.py || quote.name, quote.price, quote.symbol
        return render_template("quoted.html", quote=quote)

    else:
        # GET request to render quote.html
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Get values entered by user from form
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username is entered
        if not username:
            return apology("must provide username", 400)

        # Ensure password was entered
        elif not password:
            return apology("must provide password", 400)

        # Set password requirments ex. min length, special character, cap-letter
        l, u, d, s = 0, 0, 0, 0
        if (len(password) >=8):
            for i in password:
                # count lowercase
                if (i.islower()):
                    l += 1
                # count uppercase
                if (i.isupper()):
                    u += 1
                # count digit
                if (i.isdigit()):
                    d += 1
                # count special characters
                if (i == "@" or i == "!" or i == "<" or i == ">" or i == "^" or i == "#" or i == "$" or i == "&"):
                    s += 1
        if not (l >= 1 and u >= 1 and d >= 1 and s >= 1):
            return apology ("Invalid password: Minimun length 8 and must contain at least 1 uppercase, 1 lowercase, 1 digit, and 1 special character: @, !, <, >, ^, #, $, &", 400)

        # Ensure confirmation was entered
        elif not confirmation:
            return apology("must provide password confirmation", 400)

        # Ensure confirmation matches password
        elif confirmation != password:
            return apology("passwords do not match", 400)

        # make a hash of entered password
        hash = generate_password_hash(password)

        # enter values into database
        try:
            new_user = db.execute("INSERT INTO users (username, hash)  VALUES (?, ?)", username, hash)
        # checks if username already exists in database
        except:
            return apology("username already exists", 400)

        # Remember which user has logged in
        session["user_id"] = new_user

        # log user in imediately
        return redirect("/")

    else:
        # GET request to render register.html
        return render_template("register.html")

@app.route("/password_reset", methods=["GET", "POST"])
@login_required
def password_reset():
    if request.method == "GET":
        return render_template("password_reset.html")

    else:
        user_id = session["user_id"]

        # check if current password field is filled out
        if not request.form.get("current_pass"):
            return apology("please fill out current password", 400)

        # get current password from users database
        curr_pass_db = db.execute("SELECT hash FROM users WHERE id = ?", user_id)

        # check if current_pass is correct
        if not check_password_hash(curr_pass_db[0]["hash"], request.form.get("current_pass")):
            return apology("incorrect password", 400)

        # check if new password field is filled out
        if not request.form.get("new_pass"):
            return apology("please fill out new password", 400)

        # check if password confirmation field is filled out
        elif not request.form.get("confirmation"):
            return apology("please fill out password confirmation", 400)

        # check if new_pass and confirmation match
        elif request.form.get("new_pass") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Set password requirments ex. min length, special character, cap-letter
        l, u, d, s = 0, 0, 0, 0
        if (len(request.form.get("new_pass")) >=8):
            for i in request.form.get("new_pass"):
                # count lowercase
                if (i.islower()):
                    l += 1
                # count uppercase
                if (i.isupper()):
                    u += 1
                # count digit
                if (i.isdigit()):
                    d += 1
                # count special characters
                if (i == "@" or i == "!" or i == "<" or i == ">" or i == "^" or i == "#" or i == "$" or i == "&"):
                    s += 1
        if (l >= 1 and u >= 1 and d >= 1 and s >= 1):
            new_hash = generate_password_hash(request.form.get("new_pass"))

            db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

            flash("Password updated successfully")

            return redirect ("/")
        else:
            return apology ("Invalid password: Minimun length 8 and must contain at least 1 uppercase, 1 lowercase, 1 digit, and 1 special character: @, !, <, >, ^, #, $, &", 400)




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id = session["user_id"]
        symbols_user = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)

        return render_template("sell.html", symbols=[row["symbol"] for row in symbols_user])

    else:
        # get inputs from form and store in values
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares", type=int)

        # make sure symbol field is filled out
        if not symbol:
            return apology("please enter a stock symbol", 400)

        # use lookup function to find the entered stock symbol
        stock = lookup(symbol.upper())

        # make sure symbol entered is real
        if stock == None:
            return apology("stock symbol does not exist", 400)

        # make sure number entered in shares field is a positive int
        if not shares:
            return apology("please enter a number", 400)

        try:
            shares_form = int(request.form.get("shares"))
        except:
            return apology("invalid entry", 400)

        if shares < 0:
            return apology("enter a positive number", 400)

        # calculate transaction amount
        tranax_amnt = shares * stock["price"]

        # get the current user id from the session
        user_id = session["user_id"]

        # get the current user's cash amount from the users table in the db
        user_cash_amnt = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)

        # store the users actual cash value as a variable from the dictionary created in the line above: [ith element in dictionary = 0]['cash' amount]
        user_acnt_bal = user_cash_amnt[0]["cash"]

        user_shares_db = db.execute(
            "SELECT shares FROM holdings WHERE user_id = :id AND symbol = :symbol", id=user_id, symbol=symbol)
        user_shares = user_shares_db[0]["shares"]

        if shares > user_shares:
            return apology("You do not have enough shares")

        uptd_acnt_bal = user_acnt_bal + tranax_amnt

        # update users current account ballance
        db.execute("UPDATE users SET cash = ? WHERE id = ?", uptd_acnt_bal, user_id)

        # make varialbe to capture current date to use in the next step
        date = datetime.datetime.today()

        # update values to insert into holdings table
        new_shares = user_shares - shares
        new_total = new_shares * stock["price"]

        # update holdings table
        db.execute("UPDATE holdings SET shares = :curr_shares, total = :curr_total WHERE user_id = :user_id AND symbol = :symbol",
                        curr_shares = new_shares, curr_total = new_total, user_id = user_id, symbol = symbol)

        # fill in new transaction into database
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_amount, date, company_name) VALUES (?, ?, ?, ?, ?,?, ?)",
                    user_id, stock["symbol"], -1 * shares, stock["price"], tranax_amnt, date, stock["name"])

        # create a flash message to tell user what was purchased and for how much
        message = f"Successfully sold {stock['symbol']} for {tranax_amnt}"
        flash(message)
        return redirect("/")