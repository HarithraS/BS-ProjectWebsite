from flask import Flask, render_template, request, redirect, url_for, make_response,jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask_socketio import SocketIO,emit
from sqlalchemy import func
from models import db, User, Content,Message,Friend,File,FriendRequest,UnfriendNotify
import base64,json
from datetime import datetime

import os
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv()
# print("CLAUDE_API_KEY loaded?", bool(os.getenv("CLAUDE_API_KEY")))

msg_suggestion = OpenAI(api_key=os.getenv("CHAT_API_KEY"))

# import logging
# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

app = Flask(__name__)
socketio = SocketIO(app)


# ---------- Config ----------
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:sivakumar123@localhost:3306/data"
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:MyPassword@localhost:3306/mydatabase'

app.config["JWT_SECRET_KEY"] = "secret123"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)

db.init_app(app)
jwt = JWTManager(app)
connected_users = {}

# ---------- Socket Register & Disconnect ----------
@socketio.on("register")
def handle_register(data):
    username = data["username"]  
    connected_users[username] = request.sid
    print(f" {username} connected with SID {request.sid}")

@socketio.on("disconnect")
def handle_disconnect():
    for user, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[user]
            print(f" {user} disconnected")
            break


# ---------- JWT Error Handlers ----------
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    resp = make_response(render_template("login.html", msg="Token expired, please log in again."))
    unset_jwt_cookies(resp)
    return resp, 401


# ---------- Webapage ----------
@app.route("/")
def start():
    all_content = Content.query.order_by(Content.uploaded_at).all()
    content_data = []

    for c in all_content:
        file = None
        if c.file_data:
            file = base64.b64encode(c.file_data).decode("utf-8")

        content_data.append({
            "name": c.name,
            "email": c.email,
            "thought": c.thought,
            "filedata": file,
            "media_type": c.media_type,
            "uploaded_at": c.uploaded_at.strftime("%Y-%m-%d %H:%M")
        })

    return render_template("webpage.html", content=content_data)



# ---------- Home---------------------------------
@app.route("/home")
@jwt_required()
def home():
    current_email = get_jwt_identity()
    all_content = Content.query.filter(Content.email != current_email).order_by(Content.uploaded_at).all()
    content_data = []

    for c in all_content:
        file = None
        if c.file_data:
            file = base64.b64encode(c.file_data).decode("utf-8")

        content_data.append({
            "name": c.name,
            "email": c.email,
            "thought": c.thought,
            "filedata": file,
            "media_type": c.media_type,
            "uploaded_at": c.uploaded_at.strftime("%Y-%m-%d %H:%M")
        })

    user = User.query.filter_by(email=current_email).first()
    return render_template("home.html", content=content_data, user=user)



# ---------- Signup ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        gender = request.form.get("gender")
        raw_password = request.form.get("password")

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template("signup.html", msg="Email already exists!")

        hashed_password = generate_password_hash(raw_password)
        new_user = User(
            name=name,
            email=email,
            phone_number=phone,
            gender=gender,
            password=hashed_password
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            return render_template("login.html", msg="User registered successfully! Now Login")
        except Exception as e:
            db.session.rollback()
            return render_template("signup.html", msg="Error while registering user.")

    return render_template("signup.html")



# ---------- Login ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            email = data.get("email")
            raw_password = data.get("password")

            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, raw_password):
                token = create_access_token(identity=email)
                resp = jsonify({"success": True, "message": "Login successful"})
                set_access_cookies(resp, token)
                return resp

            return jsonify({"success": False, "message": "Invalid email or password"}), 401

    return render_template("login.html")


# ---------- Profile ----------
@app.route("/profile")
@jwt_required()
def profile():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user:
        return render_template("login.html", msg="User not found")

    all_content = Content.query.filter_by(email=current_email).all()
    content_data = []

    for c in all_content:
        file = None
        if c.file_data:
            file = base64.b64encode(c.file_data).decode("utf-8")

        content_data.append({
            "name": c.name,
            "email": c.email,
            "thought": c.thought,
            "filedata": file,
            "media_type": c.media_type,
            "uploaded_at": c.uploaded_at.strftime("%Y-%m-%d %H:%M")
        })

    return render_template("profile.html", user=user, content=content_data)



# -----------------------chat-----------------------------

@app.route("/chat")
@jwt_required()
def chat_page():
    current_email = get_jwt_identity()
    current_user = User.query.filter_by(email=current_email).first()

    # Get friend emails
    friends = Friend.query.filter_by(user_email=current_email).all()
    friend_emails = {f.friend_email for f in friends}

    messages = Message.query.filter(
        (Message.sender == current_email) | (Message.receiver == current_email)
    ).all()

    messaged_emails = set()
    for msg in messages:
        if msg.sender != current_email:
            messaged_emails.add(msg.sender)
        if msg.receiver != current_email:
            messaged_emails.add(msg.receiver)

    active_friend_emails = friend_emails & messaged_emails

    active_friends = []
    for email in active_friend_emails:
        user = User.query.filter_by(email=email).first()
        if user:

            user.unread_count = Message.query.filter_by(
                sender=user.email,
                receiver=current_email,
                is_new_msg=True
            ).count()

            # Get last message timestamp
            last_msg = Message.query.filter(
                ((Message.sender == user.email) & (Message.receiver == current_email)) |
                ((Message.sender == current_email) & (Message.receiver == user.email))
            ).order_by(Message.timestamp.desc()).first()

            if last_msg and last_msg.timestamp:
              
                user.last_msg_time = last_msg.timestamp.isoformat()
            else:
                user.last_msg_time = None

            active_friends.append(user)

    # Sort by last message time 
    active_friends.sort(
        key=lambda u: datetime.fromisoformat(u.last_msg_time) if u.last_msg_time else datetime.min,
        reverse=True
    )

    return render_template("chat.html", users=active_friends, user=current_user)


# ------------search in chat -----------------------------
@app.route("/search_friends", methods=["POST"])
@jwt_required()
def search_friends():
    current_email = get_jwt_identity()
    data = request.get_json()
    query = data.get("query", "").strip().lower()
    friends = Friend.query.filter_by(user_email=current_email).all()
    friend_emails = [f.friend_email for f in friends]
    if query:
        results = User.query.filter(
            User.email.in_(friend_emails),
            db.func.lower(User.name).like(f"%{query}%")
        ).all()
    else:
        results = User.query.filter(User.email.in_(friend_emails)).all()
    return jsonify([
        {
            "name": u.name,
            "email": u.email
        } for u in results
    ])




# --------------mark read----------------------

@app.route("/mark_read", methods=["POST"])
@jwt_required()
def mark_messages_read():
    data = request.json
    sender_email = data.get("sender_email")
    receiver_email = data.get("receiver_email")
    
    current_email = get_jwt_identity()
    if current_email != receiver_email:
        return jsonify({"error": "Unauthorized"}), 403

    Message.query.filter_by(
        sender=sender_email,
        receiver=receiver_email,
        is_new_msg=True
    ).update({"is_new_msg": False})
    db.session.commit()
    return jsonify({"success": True})


@app.context_processor
@jwt_required(optional=True)
def inject_nav_counts():
    try:
        current_email = get_jwt_identity()
        if not current_email:
            return dict(pending_req_count=0, unread_msg_count=0)

        # Pending friend requests
        pending_req_count = FriendRequest.query.filter_by(
            receiver_email=current_email, status="pending"
        ).count()

        # Unread messages
        unread_msg_count = Message.query.filter_by(
            receiver=current_email, is_new_msg=True
        ).count()

        return dict(
            pending_req_count=pending_req_count,
            unread_msg_count=unread_msg_count
        )
    except Exception:
        return dict(pending_req_count=0, unread_msg_count=0)
    

    
# -------------------chat suggestion with api key---------------

@app.route("/chat_recommendations", methods=["POST"])
@jwt_required(optional=True)
def chat_recommendations():
    data = request.get_json()
    current_msg = data.get("message")

    if not current_msg:
        return jsonify({"error": "No message provided"}), 400

    response = msg_suggestion.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {
            "role": "system",
            "content": (
                "You are a friendly chat assistant. "
                "Suggest 3 very short (2–6 words) natural replies suitable for casual texting. "
                "No numbering, no quotes, just the replies."
            )
        },
        {"role": "user", "content": current_msg}
    ]
)

    suggestions = response.choices[0].message.content.strip().split("\n")
    return jsonify({"suggestions": suggestions})

# --------------friends------------------------
@app.route("/friends")
@jwt_required()
def friends_page():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()

    msg = request.args.get("msg")

    received_files = File.query.filter(File.receiver_email.contains([current_email])).order_by(File.uploaded_at.desc()).all()
    files = received_files

    friends = Friend.query.filter_by(user_email=current_email).all()

    sent_requests = FriendRequest.query.filter(
        FriendRequest.sender_email == current_email,
        FriendRequest.status.in_(["pending", "rejected", "unfriended"])
    ).all()

    unfriended = UnfriendNotify.query.filter_by(sender_email=current_email).all()

    pending_req_count = FriendRequest.query.filter_by(
        receiver_email=current_email, status="pending"
    ).count()

    return render_template(
        "friends.html",
        friends=friends,
        files=files,
        user=user,
        msg=msg,
        pending_req_count=pending_req_count,
        sent_requests=sent_requests,
        unfriended=unfriended  
    )


# ---------------check and add -----------------

@app.route('/check_and_add_friend', methods=['POST'])
@jwt_required()
def check_and_add_friend():
    current_email = get_jwt_identity()
    friend_email = request.form.get('friend_email')

    friends = Friend.query.filter_by(user_email=current_email).all()
    user_exists = User.query.filter_by(email=friend_email).first()
    show_add_button = bool(user_exists)
    msg = None if user_exists else "User not found!"

    # ---------- Check Unfriend ----------
    unfriended = UnfriendNotify.query.filter(
        ((UnfriendNotify.sender_email == current_email) & (UnfriendNotify.receiver_email == friend_email)) |
        ((UnfriendNotify.sender_email == friend_email) & (UnfriendNotify.receiver_email == current_email))
    ).first()

    if unfriended:
        if unfriended.sender_email == current_email:
            msg = f"You already unfriended {friend_email}. You can send a request again if you want."
        else:
            msg = f"{friend_email} unfriended you. You can send a request again if you want."
        show_add_button = True  
        return render_template(
            'friends.html',
            friend_email=friend_email,
            show_add_button=show_add_button,
            msg=msg,
            friends=friends,
            user=User.query.filter_by(email=current_email).first()
        )

    # ---------- Check Rejected Friend Requests ----------
    rejected_req = FriendRequest.query.filter(
        ((FriendRequest.sender_email == current_email) & (FriendRequest.receiver_email == friend_email) & (FriendRequest.status == "rejected")) |
        ((FriendRequest.sender_email == friend_email) & (FriendRequest.receiver_email == current_email) & (FriendRequest.status == "rejected"))
    ).first()

    if rejected_req:
        if rejected_req.sender_email == current_email:
            msg = f"You had sent a request to {friend_email}, but they rejected it. You can send a request again if you want."
        else:
            msg = f"{friend_email} had sent you a request, but you rejected it. You can send a request again if you want."
        show_add_button = True 
        return render_template(
            'friends.html',
            friend_email=friend_email,
            show_add_button=show_add_button,
            msg=msg,
            friends=friends,
            user=User.query.filter_by(email=current_email).first()
        )

    # ---------- Check Pending Friend Requests ----------
    existing_req = FriendRequest.query.filter(
        ((FriendRequest.sender_email == current_email) & (FriendRequest.receiver_email == friend_email) & (FriendRequest.status == "pending")) |
        ((FriendRequest.sender_email == friend_email) & (FriendRequest.receiver_email == current_email) & (FriendRequest.status == "pending"))
    ).first()

    if existing_req:
        if existing_req.sender_email == current_email:
            msg = f"You already sent a friend request to {friend_email}. Waiting for their response."
            show_add_button = False
        else:
            msg = f"{friend_email} has already sent you a friend request. Check your requests page to accept or reject it."
            show_add_button = False
        return render_template(
            'friends.html',
            friend_email=friend_email,
            show_add_button=show_add_button,
            msg=msg,
            friends=friends,
            user=User.query.filter_by(email=current_email).first()
        )

    # ---------- If user exists and no unfriend/rejected/pending ----------
    return render_template(
        'friends.html',
        friend_email=friend_email,
        show_add_button=show_add_button,
        msg=msg,
        friends=friends,
        user=User.query.filter_by(email=current_email).first()
    )



# -----------------by email---------------------------
@app.route("/send_req", methods=["POST"])
@jwt_required()
def send_req():
    current_email = get_jwt_identity()
    receiver_email = request.form.get("friend_email")

    current_user = User.query.filter_by(email=current_email).first()
    friends = Friend.query.filter_by(user_email=current_email).all() 

    if not receiver_email:
        return render_template('friends.html', msg="No email provided", friend_email=receiver_email, friends=friends, user=current_user)
    if receiver_email == current_email:
        return render_template('friends.html', msg="Cannot send request to yourself", friend_email=receiver_email, friends=friends, user=current_user)

    if Friend.query.filter_by(user_email=current_email, friend_email=receiver_email).first():
        return render_template('friends.html', msg="Already friends", friend_email=receiver_email, friends=friends, user=current_user)

    if FriendRequest.query.filter_by(sender_email=current_email, receiver_email=receiver_email, status="pending").first():
        return render_template('friends.html', msg="Request already sent", friend_email=receiver_email, friends=friends, user=current_user)

    unfriended = UnfriendNotify.query.filter(
        ((UnfriendNotify.sender_email == current_email) & (UnfriendNotify.receiver_email == receiver_email)) |
        ((UnfriendNotify.sender_email == receiver_email) & (UnfriendNotify.receiver_email == current_email))
    ).first()

    if unfriended:
        # Delete unfriended record before sending request
        db.session.delete(unfriended)
        db.session.commit()

    # Add friend request
    new_req = FriendRequest(sender_email=current_email, receiver_email=receiver_email)
    db.session.add(new_req)
    db.session.commit()
    if receiver_email in connected_users:
        socketio.emit(
            "friend_request_received",
            {"from": current_email},
            room=connected_users[receiver_email]
        )

    return render_template('friends.html', msg=f"Friend request sent to {receiver_email}!", friend_email=receiver_email, friends=friends, user=current_user)





# -------------send_request---------------
@app.route("/send_request", methods=["POST"])
@jwt_required()
def send_request():
    current_email = get_jwt_identity()
    if not request.is_json:
        return jsonify(success=False, message="Invalid request"), 400

    data = request.get_json()
    receiver_email = data.get("friend_email")

    if not receiver_email:
        return jsonify(success=False, message="No email provided")
    if receiver_email == current_email:
        return jsonify(success=False, message="Cannot send request to yourself")

    # Already friends?
    if Friend.query.filter_by(user_email=current_email, friend_email=receiver_email).first():
        return jsonify(success=False, message="Already friends")

    # Request already pending?
    if FriendRequest.query.filter_by(sender_email=current_email, receiver_email=receiver_email, status="pending").first():
        return jsonify(success=False, message="Request already sent")

    # Check unfriended
    unfriended = UnfriendNotify.query.filter(
        ((UnfriendNotify.sender_email == current_email) & (UnfriendNotify.receiver_email == receiver_email)) |
        ((UnfriendNotify.sender_email == receiver_email) & (UnfriendNotify.receiver_email == current_email))
    ).first()

    if unfriended:
        # Return special flag to trigger "Do you want to resend?" alert in JS
        return jsonify(success=False, unfriended=True, message=(
            f"You already unfriended {receiver_email}!" if unfriended.sender_email == current_email
            else f"{receiver_email} unfriended you!"
        ))

    # If no unfriended, create request normally
    new_req = FriendRequest(sender_email=current_email, receiver_email=receiver_email)
    db.session.add(new_req)
    db.session.commit()
    # Emit notification to receiver if online
    if receiver_email in connected_users:
        socketio.emit(
            "friend_request_received",
            {"from": current_email},
            room=connected_users[receiver_email]
        )

    return jsonify(success=True, message=f"Friend request sent to {receiver_email}!")



@app.route("/resend_request_after_unfriend", methods=["POST"])
@jwt_required()
def resend_request_after_unfriend():
    current_email = get_jwt_identity()
    data = request.get_json()
    receiver_email = data.get("friend_email")

    # Delete unfriended record
    unfriended = UnfriendNotify.query.filter(
        ((UnfriendNotify.sender_email == current_email) & (UnfriendNotify.receiver_email == receiver_email)) |
        ((UnfriendNotify.sender_email == receiver_email) & (UnfriendNotify.receiver_email == current_email))
    ).first()
    if unfriended:
        db.session.delete(unfriended)
        db.session.commit()

    # Send new friend request
    new_req = FriendRequest(sender_email=current_email, receiver_email=receiver_email)
    db.session.add(new_req)
    db.session.commit()

    return jsonify(success=True, message=f"Friend request sent to {receiver_email}!")



@app.route("/force_send_request", methods=["POST"])
@jwt_required()
def force_send_request():
    current_email = get_jwt_identity()
    data = request.get_json()
    receiver_email = data.get("friend_email")

    # Delete unfriended record
    UnfriendNotify.query.filter(
        ((UnfriendNotify.sender_email == current_email) & (UnfriendNotify.receiver_email == receiver_email)) |
        ((UnfriendNotify.sender_email == receiver_email) & (UnfriendNotify.receiver_email == current_email))
    ).delete()

    # Create new friend request
    new_req = FriendRequest(sender_email=current_email, receiver_email=receiver_email)
    db.session.add(new_req)
    db.session.commit()

    return jsonify(success=True, message=f"Friend request sent again to {receiver_email}!")




# ----------------- UPLOAD FILE -----------------

@app.route("/upload_file", methods=["POST"])
@jwt_required()
def upload_file():
    current_email = get_jwt_identity()

    file = request.files.get("file")
    if not file:
        return redirect(url_for("friends_page", msg="No file selected"))

    file_data = file.read()

    receivers = request.form.getlist("receivers")
    if not receivers:
        return redirect(url_for("friends_page", msg="Please select at least one friend!"))

    time_interval_in_mins = request.form.get("time_interval")
    if not time_interval_in_mins:
        return redirect(url_for("friends_page", msg="Please select a time!"))

    new_file = File(
        user_email=current_email,
        file_data=file_data,
        receiver_email=json.dumps(receivers), 
        time_interval_in_mins=int(time_interval_in_mins),
        filename=file.filename            
    )

    db.session.add(new_file)
    db.session.commit()

    return redirect(url_for("friends_page", msg="File sent successfully!"))


# ----------------- VIEW REQUESTS -----------------
@app.route('/requests')
@jwt_required()
def view_requests():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()

    # ----------------- Received requests -----------------
    requests = FriendRequest.query.filter_by(
        receiver_email=user.email,
        status="pending"
    ).all()

    valid_requests = []
    for req in requests:
        sender = User.query.filter_by(email=req.sender_email).first()
        if sender:
            valid_requests.append(req)
        else:
            db.session.delete(req)
    db.session.commit()

    # ----------------- Friends -----------------
    friends = Friend.query.filter(
        (Friend.user_email == user.email) | (Friend.friend_email == user.email)
    ).all()
    friends_set = set()
    for f in friends:
        friend_email = f.friend_email if f.user_email == user.email else f.user_email
        if User.query.filter_by(email=friend_email).first():  
            friends_set.add(friend_email)
        else:
            db.session.delete(f)
    db.session.commit()

    # ----------------- Sent requests -----------------
    sent_requests = FriendRequest.query.filter(
        FriendRequest.sender_email == user.email,
        FriendRequest.status.in_(["pending", "rejected"])
    ).all()
    valid_sent_requests = []
    for req in sent_requests:
        receiver = User.query.filter_by(email=req.receiver_email).first()
        if receiver:
            valid_sent_requests.append(req)
        else:
            db.session.delete(req)
    db.session.commit()

    # ----------------- Unfriend notifications -----------------
    unfriended_notifications = UnfriendNotify.query.filter_by(receiver_email=user.email).all()
    my_unfriend_actions = UnfriendNotify.query.filter_by(sender_email=user.email).all()

    for note in unfriended_notifications + my_unfriend_actions:
        other_email = note.sender_email if note.sender_email != user.email else note.receiver_email
        if not User.query.filter_by(email=other_email).first():
            db.session.delete(note)
    db.session.commit()

    # ----------------- Friend Suggestions -----------------
    suggestions = {}
    my_friends = list(friends_set)

    for f_email in my_friends:
        # Get f_email's friends
        their_friends = Friend.query.filter_by(user_email=f_email).all()

        for tf in their_friends:
            potential = tf.friend_email

            # Skip if same person
            if potential == user.email:
                continue

            # Skip if already friend
            if Friend.query.filter_by(user_email=user.email, friend_email=potential).first():
                continue

            # Skip if pending or accepted friend request exists
            if FriendRequest.query.filter(
                ((FriendRequest.sender_email == user.email) & (FriendRequest.receiver_email == potential)) |
                ((FriendRequest.sender_email == potential) & (FriendRequest.receiver_email == user.email))
            ).filter(FriendRequest.status.in_(["pending", "accepted"])).first():
                continue

            # Add potential suggestion with mutual friend tracking
            if potential not in suggestions:
                suggestions[potential] = {"email": potential, "mutual_friends": set()}
            suggestions[potential]["mutual_friends"].add(f_email)

    # Convert dict → list and sort by number of mutual friends (descending)
    suggestion_list = [
        {"email": s["email"], "mutual_friends": list(s["mutual_friends"])}
        for s in suggestions.values()
    ]
    suggestion_list.sort(key=lambda x: len(x["mutual_friends"]), reverse=True)

    return render_template(
        'requests.html',
        user=user,
        requests=valid_requests,
        friends=list(friends_set),
        sent_requests=valid_sent_requests,
        unfriended_notifications=unfriended_notifications,
        my_unfriend_actions=my_unfriend_actions,
        suggestions=suggestion_list 
    )



# ------------------------unfriend------------------------
@app.route('/unfriend/<friend_email>', methods=["POST"])
@jwt_required()
def unfriend(friend_email):
    current_email = get_jwt_identity()

    notification = UnfriendNotify(
        sender_email=current_email,     
        receiver_email=friend_email     
    )
    db.session.add(notification)

    friendships = Friend.query.filter(
        ((Friend.user_email == current_email) & (Friend.friend_email == friend_email)) |
        ((Friend.user_email == friend_email) & (Friend.friend_email == current_email))
    ).all()

    if friendships:
        for f in friendships:
            db.session.delete(f)

    db.session.commit()

    return redirect(url_for('view_requests', msg=f"Unfriended {friend_email} successfully"))




# ----------------- RESPOND TO REQUEST -----------------
@app.route("/respond_request/<int:req_id>/<string:action>")
@jwt_required()
def respond_request(req_id, action):
    current_email = get_jwt_identity()
    req = FriendRequest.query.get(req_id)

    if not req or req.receiver_email != current_email:
        return redirect(url_for("view_requests", msg="Invalid request"))

    if action == "accept":
        req.status = "accepted"
        # Create friendship
        db.session.add(Friend(user_email=req.sender_email, friend_email=req.receiver_email))
        db.session.add(Friend(user_email=req.receiver_email, friend_email=req.sender_email))


        old_requests = FriendRequest.query.filter(
            FriendRequest.sender_email == req.sender_email,
            FriendRequest.receiver_email == req.receiver_email,
            FriendRequest.status.in_(["rejected", "unfriended"])
        ).all()
        for r in old_requests:
            db.session.delete(r)

    elif action == "reject":
        req.status = "rejected"

    db.session.commit()
    if action == "accept":
        if req.sender_email in connected_users:
            socketio.emit("friends_updated", room=connected_users[req.sender_email])
        if req.receiver_email in connected_users:
            socketio.emit("friends_updated", room=connected_users[req.receiver_email])

    return redirect(url_for("view_requests", msg=f"Request {action}ed"))

# ---------- Edit Profile ----------
@app.route("/edit", methods=["POST"])
@jwt_required()
def edit():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user:
        return render_template("login.html", msg="User not found")
    return render_template("edit.html", user=user)


# ---------- update Profile ----------
@app.route("/update", methods=["POST"])
@jwt_required()
def update():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if not user:
        return render_template("login.html", msg="User not found")

    new_name = request.form.get("name")
    new_phone = request.form.get("phone")
    new_gender = request.form.get("gender")

    if new_name == user.name and new_phone == user.phone_number and new_gender == user.gender:
        return render_template("edit.html", user=user, msg="No changes made!")

    user.name = new_name
    user.phone_number = new_phone
    user.gender = new_gender
    db.session.commit()

    return render_template("edit.html", user=user, msg="Profile updated successfully")



# ---------- Add Content ----------
@app.route("/add_content", methods=["GET"])
def add_content():
    email = request.args.get("email")
    name = request.args.get("name")

    if not email:
        return render_template("login.html", msg="User not found")

    return render_template("add.html", email=email, name=name)


# ---------- conform----------
@app.route("/conform", methods=["POST"])
def conform():
    email = request.form.get("email")
    name = request.form.get("name")
    thought = request.form.get("thought")
    uploaded_file = request.files.get("file")

    file_data = None
    media_type = None

    if uploaded_file and uploaded_file.filename != "":
        file_data = uploaded_file.read()
        filename = uploaded_file.filename.lower()

        if filename.endswith((".png", ".jpg", ".jpeg", ".gif")):
            media_type = "image"
        elif filename.endswith(".mp4"):
            media_type = "video"
        elif filename.endswith(".pdf"):
            media_type = "pdf"
        elif filename.endswith((".doc", ".docx")):
            media_type = "doc"
        elif filename.endswith(".ppt"):
            media_type = "ppt"
        elif filename.endswith(".txt"):
            media_type = "txt"
        else:
            media_type = "other"

    new_content = Content(
        email=email,
        name=name,
        thought=thought,
        file_data=file_data,
        media_type=media_type
    )

    db.session.add(new_content)
    db.session.commit()

    return redirect(url_for("profile"))


# ---------- Delete Profile ----------
@app.route("/delete", methods=["POST"])
@jwt_required()
def delete():
    current_email = get_jwt_identity()
    user = User.query.filter_by(email=current_email).first()
    if user:
        db.session.delete(user)
        db.session.commit()
    return render_template("login.html", msg="Profile deleted.")


# ---------DEl Record files in profile-----------------

@app.route("/del", methods=["POST"])
@jwt_required()
def delete_content():
    current_email = get_jwt_identity()
    content_id = request.form.get("content_id")

    if not content_id:
        return redirect(url_for("profile"))

    content_to_delete = Content.query.get(content_id)

    if content_to_delete and content_to_delete.email == current_email:
        db.session.delete(content_to_delete)
        db.session.commit()

    return redirect(url_for("profile"))


# ---------- Logout ----------
@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    unset_jwt_cookies(resp)
    return resp


# ---------- Save message to DB ----------

@socketio.on("private_message")
def handle_private_message(data):
    sender = data["sender"]
    receiver = data["receiver"]
    message = data["message"]

    new_msg = Message(sender=sender, receiver=receiver, message=message, is_new_msg=True)
    db.session.add(new_msg)
    db.session.commit()

    timestamp = new_msg.timestamp.isoformat() 

    if receiver in connected_users:
        emit("private_message", {
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": timestamp  
        }, room=connected_users[receiver])


# ---------------- GET MESSAGES ----------------
@app.route("/messages/<sender>/<receiver>")
@jwt_required()
def get_messages(sender, receiver):
    current_email = get_jwt_identity()

    if current_email not in [sender, receiver]:
        return jsonify({"error": "Unauthorized"}), 403

    msgs = Message.query.filter(
        ((Message.sender == sender) & (Message.receiver == receiver)) |
        ((Message.sender == receiver) & (Message.receiver == sender))
    ).order_by(Message.timestamp).all()

    messages_data = [
    {
        "sender": m.sender,
        "receiver": m.receiver,
        "message": m.message,
        "timestamp": m.timestamp.isoformat()  
    }
    for m in msgs
]


    return jsonify({"messages": messages_data})

if __name__=="__main__":
    socketio.run(app,debug=True)

# if __name__ == "__main__":
#     socketio.run(app, host="0.0.0.0", port=5000, debug=True)


# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)

