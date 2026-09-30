import os
import secrets
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    UserMixin,
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

app = Flask(__name__)

app.config['MEDIA_ROOT'] = os.environ.get('MEDIA_ROOT', os.path.join(app.root_path, 'storage'))
app.config['UPLOAD_FOLDER'] = os.path.join(app.config['MEDIA_ROOT'], 'videos')
app.config['PROFILE_PHOTO_FOLDER'] = os.path.join(app.config['MEDIA_ROOT'], 'profile_photos')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'nexus_stream_dev_key_change_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(app.instance_path, 'nexus.db')
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1 GB per request

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_PHOTO_FOLDER'], exist_ok=True)
os.makedirs(app.instance_path, exist_ok=True)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to continue.'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_photo = db.Column(db.String(255), nullable=True)
    recovery_code_hash = db.Column(db.String(255), nullable=True)


class video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=db.func.now())
    categories = db.Column(db.String(50), nullable=False)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )
    uploader = db.relationship('User', backref='videos')


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {
        'jpg', 'jpeg', 'png', 'webp'
    }


def allowed_video(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {
        'mp4', 'webm', 'mov', 'm4v'
    }


def migrate_user_columns():
    """Add new nullable User columns when an older local SQLite DB is reused."""
    if not app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        return

    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    if 'user' not in inspector.get_table_names():
        return

    columns = {column['name'] for column in inspector.get_columns('user')}
    with db.engine.begin() as connection:
        if 'profile_photo' not in columns:
            connection.execute(text('ALTER TABLE user ADD COLUMN profile_photo VARCHAR(255)'))
        if 'recovery_code_hash' not in columns:
            connection.execute(text('ALTER TABLE user ADD COLUMN recovery_code_hash VARCHAR(255)'))


# ==========================================
# AUTHENTICATION
# ==========================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form_username = request.form.get('username', '').strip()
        form_password = request.form.get('password', '')

        if len(form_username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return redirect(url_for('register'))

        if len(form_password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=form_username).first()
        if existing_user:
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('register'))

        recovery_code = secrets.token_hex(4).upper()
        new_user = User(
            username=form_username,
            password_hash=generate_password_hash(form_password),
            recovery_code_hash=generate_password_hash(recovery_code)
        )

        db.session.add(new_user)
        db.session.commit()

        return render_template(
            'registration_success.html',
            username=form_username,
            recovery_code=recovery_code
        )

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        form_username = request.form.get('username', '').strip()
        form_password = request.form.get('password', '')

        user = User.query.filter_by(username=form_username).first()

        if user and check_password_hash(user.password_hash, form_password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))

        flash('Invalid username or password. Please try again.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        recovery_code = request.form.get('recovery_code', '').strip().upper()
        new_password = request.form.get('new_password', '')

        user = User.query.filter_by(username=username).first()

        if not user or not user.recovery_code_hash:
            flash('Invalid username or recovery code.', 'error')
            return redirect(url_for('forgot_password'))

        # Recovery codes are normalized so copied codes still work even if
        # the user accidentally adds spaces or uses lowercase letters.
        recovery_code = ''.join(recovery_code.split()).upper()

        if not check_password_hash(user.recovery_code_hash, recovery_code):
            flash('Invalid username or recovery code.', 'error')
            return redirect(url_for('forgot_password'))

        if len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'error')
            return redirect(url_for('forgot_password'))

        user.password_hash = generate_password_hash(new_password)
        # Make the recovery code truly one-time-use.
        user.recovery_code_hash = None
        db.session.commit()

        flash('Password reset successfully. Your recovery code has been used and is no longer valid.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()

        current_password = request.form.get('current_password', '')
        recovery_code = request.form.get('recovery_code', '').strip()

        new_password = request.form.get('new_password', '')
        photo = request.files.get('profile_photo')

        # -----------------------------------------
        # BASIC USERNAME VALIDATION
        # -----------------------------------------
        if len(new_username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return redirect(url_for('profile'))

        changing_username = new_username != current_user.username
        changing_password = bool(new_password)

        # -----------------------------------------
        # PASSWORD / USERNAME CHANGE
        # -----------------------------------------
        if changing_username or changing_password:

            # Check whether the user supplied a current password
            current_password_valid = False

            if current_password:
                current_password_valid = check_password_hash(
                    current_user.password_hash,
                    current_password
                )

            # Check whether the user supplied the recovery code
            recovery_code_valid = False

            if recovery_code and current_user.recovery_code_hash:
                normalized_code = ''.join(recovery_code.split()).upper()

                recovery_code_valid = check_password_hash(
                    current_user.recovery_code_hash,
                    normalized_code
                )

            # User must provide either:
            # 1. correct current password
            # OR
            # 2. correct recovery code
            if not current_password_valid and not recovery_code_valid:
                flash(
                    'Enter your current password OR your recovery code.',
                    'error'
                )
                return redirect(url_for('profile'))

            # -----------------------------------------
            # CHANGE USERNAME
            # -----------------------------------------
            if changing_username:
                existing_user = User.query.filter_by(
                    username=new_username
                ).first()

                if existing_user and existing_user.id != current_user.id:
                    flash('That username is already taken.', 'error')
                    return redirect(url_for('profile'))

                current_user.username = new_username

            # -----------------------------------------
            # CHANGE PASSWORD
            # -----------------------------------------
            if changing_password:

                if len(new_password) < 6:
                    flash(
                        'New password must be at least 6 characters.',
                        'error'
                    )
                    return redirect(url_for('profile'))

                current_user.password_hash = generate_password_hash(
                    new_password
                )

                # If recovery code was used, make it one-time-use.
                if recovery_code_valid:
                    current_user.recovery_code_hash = None

        # -----------------------------------------
        # PROFILE PHOTO
        # -----------------------------------------
        if photo and photo.filename:

            if not allowed_image(photo.filename):
                flash(
                    'Profile photo must be JPG, JPEG, PNG, or WEBP.',
                    'error'
                )
                return redirect(url_for('profile'))

            filename = secure_filename(photo.filename)

            extension = filename.rsplit('.', 1)[1].lower()

            unique_name = (
                f'user_{current_user.id}_'
                f'{secrets.token_hex(8)}.'
                f'{extension}'
            )

            photo.save(
                os.path.join(
                    app.config['PROFILE_PHOTO_FOLDER'],
                    unique_name
                )
            )

            current_user.profile_photo = unique_name

        # -----------------------------------------
        # SAVE EVERYTHING
        # -----------------------------------------
        db.session.commit()

        flash('Profile updated successfully.', 'success')

        return redirect(url_for('profile'))

    return render_template('profile.html')


@app.route('/video/<int:video_id>/delete', methods=['POST'])
@login_required
def delete_video(video_id):
    selected_video = video.query.get_or_404(video_id)

    # Only the user who uploaded the video is allowed to delete it.
    if selected_video.user_id != current_user.id:
        flash('You can only delete videos that you uploaded.', 'error')
        return redirect(url_for('my_videos'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], selected_video.file_path)

    try:
        db.session.delete(selected_video)
        db.session.commit()

        if os.path.exists(file_path):
            os.remove(file_path)

        flash('Video deleted successfully.', 'success')
    except Exception:
        db.session.rollback()
        flash('The video could not be deleted. Please try again.', 'error')

    return redirect(url_for('my_videos'))


@app.route('/my-videos')
@login_required
def my_videos():
    user_videos = video.query.filter_by(user_id=current_user.id).order_by(
        video.upload_date.desc()
    ).all()
    return render_template('my_videos.html', videos=user_videos)


# ==========================================
# HOME & WATCH
# ==========================================

@app.route('/')
def home():
    category = request.args.get('category')

    if category:
        videos = video.query.filter_by(categories=category).order_by(
            video.upload_date.desc()
        ).all()
    else:
        videos = video.query.order_by(video.upload_date.desc()).all()

    return render_template('index.html', videos=videos)


@app.route('/watch/<int:video_id>')
def watch(video_id):
    selected_video = video.query.get_or_404(video_id)
    return render_template('watch.html', video=selected_video)


# ==========================================
# VIDEO UPLOAD
# ==========================================

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        title = request.form.get('title', '').strip()
        category = request.form.get('categories', '').strip()
        description = request.form.get('description', '').strip()

        if not file or not file.filename:
            flash('Please select a video.', 'error')
            return redirect(url_for('upload'))

        if not title or not category:
            flash('Title and category are required.', 'error')
            return redirect(url_for('upload'))

        if not allowed_video(file.filename):
            flash('Allowed video formats: MP4, WEBM, MOV, M4V.', 'error')
            return redirect(url_for('upload'))

        filename = secure_filename(file.filename)
        extension = filename.rsplit('.', 1)[1].lower()
        unique_name = f'{secrets.token_hex(12)}.{extension}'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)

        try:
            file.save(file_path)

            new_video = video(
                title=title,
                categories=category,
                description=description,
                file_path=unique_name,
                user_id=current_user.id
            )

            db.session.add(new_video)
            db.session.commit()

            flash('Video uploaded successfully!', 'success')
            return redirect(url_for('my_videos'))

        except Exception:
            db.session.rollback()
            if os.path.exists(file_path):
                os.remove(file_path)
            flash('Upload failed. Please try again.', 'error')
            return redirect(url_for('upload'))

    return render_template('upload.html')


# ==========================================
# MEDIA DELIVERY
# ==========================================

@app.route('/media/videos/<path:filename>')
def media_video(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/media/profile/<path:filename>')
def media_profile(filename):
    return send_from_directory(app.config['PROFILE_PHOTO_FOLDER'], filename)


# ==========================================
# DATABASE
# ==========================================

with app.app_context():
    db.create_all()
    migrate_user_columns()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
