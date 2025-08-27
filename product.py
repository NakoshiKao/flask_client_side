import os
from flask import Flask, render_template, request, url_for, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import CheckConstraint, or_

app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS")

db = SQLAlchemy(app)
migrate = Migrate(app, db)

product_category = db.Table('product_category',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id', primary_key=True)),
    db.Column('category_id', db.Integer, db.ForeignKey('category.id', primary_key=True))
)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    products = db.relationship('Product', secondary=product_category,
                               backref=db.backref('category', lazy='dynamic'), lazy='dynamic')


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    available = db.Column(db.Boolean, nullable=False)
    category_id = db.Column(CheckConstraint(table=Category), unique=False, nullable=False)
    description = db.Column(db.Text, nullable=False)
    reviews_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=True)
    product_images = db.relationship('ProductImage', backref='product', lazy=True)


class ProductImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, nullable=False)
    product = db.relationship('Product', backref='reviews', lazy=True)
    review_image = db.relationship('ProductImage', backref='review', lazy=True)


class ReviewImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)


add_category = Category(name='Books')
add_product = Product(name='Book', price=100, available=True,category_id=1, description='Green Book')

db.session.add_all([add_category, add_product])
db.session.commit()
@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', type=str, default='')
    category_id = request.args.get('category', type=int)
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    available = request.args.get('available', type=int)

    query = Product.query

    if search:
        query = query.filter( or_(Product.name.ilike(f'%{search}%'),
                                  (Product.description.ilike(f'%{search}%'),)
                                  )
                              )
    if category_id:
        query = query.filter_by(category_id=category_id)

    if min_price is not None:
        query = query.filter(Product.price >= min_price)

    if max_price is not None:
        query = query.filter(Product.price <= max_price)

    if available is not None:
        query = query.filter_by(available == bool(available))

    products_paginated = query.paginate(page=page, per_page=5)
    categories = Category.query.all()

    return render_template('product/products.html', products=products_paginated.items, categories=categories)
    # return jsonify({
    #     "page": products_paginated.page,
    #     "pages": products_paginated.pages,
    #     "total": products_paginated.total,
    #     "products": [
    #         {
    #             "id": p.id,
    #             "name": p.name,
    #             "description": p.description,
    #             "price": p.price,
    #             "available": p.available,
    #             "product_images": p.product_images,
    #             "category": p.category.name if p.category else None,
    #             "reviews": p.reviews,
    #         }for p in products_paginated.items]})


@app.route('/products/<int:id>', methods=["GET", "POST"])
def product_details(product_id):
    product = Product.query.get_or_404(product_id)
    review = Review.query.filter_by(review_id=product.review_id).all()
    return render_template('product/product_details.html', product=product, review=review)
    # return jsonify({
    #     "id": product.id,
    #     "name": product.name,
    #     "description": product.description,
    #     "price": product.price,
    #     "available": product.available,
    #     "product_images": product.product_images,
    #     "category": product.category.name if product.category else None,
    #     "reviews": [
    #         {"id": r.id, "content": r.content, "rating": r.rating}
    #         for r in product.reviews
    #     ]
    # })


