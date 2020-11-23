#!/usr/bin/env python
# coding: utf-8

# In[57]:


import os
import ast

from flask import Flask, render_template, url_for, flash, request, session, redirect
from flask_paginate import Pagination, get_page_parameter
from flask_dance.contrib.google import make_google_blueprint, google
#from DataModel import *
get_ipython().run_line_magic('run', 'DataModel.ipynb')

app = Flask(__name__)
app.secret_key = 'random string'

#Configuration
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "334058460382-5m4glqh01o8ta20m7djbhco1e333tm95.apps.googleusercontent.com"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "pbqXJXkt1g-KcadEtYgJTImO"
google_bp = make_google_blueprint(scope=["profile", "email"])
app.register_blueprint(google_bp, url_prefix="/login")

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'


@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                 endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)

@app.route('/')
def index():
    print("Index Page")
    if google.authorized:
        resp = google.get("/oauth2/v1/userinfo")
        
        username = resp.json()["email"]
        session['userid'] = username
        assert resp.ok, resp.text
    
        recommendations = Recommendations(username)
        new_user = recommendations.check_if_newuser()
            
        if(new_user == "No"):
            listings, reviews = recommendations.collaborative_filtering()   
        else:
            listings, reviews = recommendations.random_recommendations()
    
    if 'userid' in session:
        return(render_template('user.html', UserId = username, new_user = new_user, listings = listings, reviews = reviews))
    
    return(render_template('index.html'))

@app.route('/loginsignuppage')
def login_signup():
    return(render_template('login.html'))

@app.route('/hostloginsignup')
def hostlogin_signup():
    return(render_template('hostlogin.html'))


@app.route('/googleauth')
def google_auth():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v1/userinfo")
    
    username = resp.json()["email"]
    print(username)
    User(username).set_password(username, "")
    
    session['userid'] = username
    assert resp.ok, resp.text
        
    user = User(username)
    recommendations = Recommendations(username)
    new_user = recommendations.check_if_newuser()
        
    if(new_user == "No"):
        listings, reviews = recommendations.collaborative_filtering()   
    else:
        listings, reviews = recommendations.random_recommendations()
        
    return(render_template('user.html', UserId = username, new_user = new_user, listings = listings, reviews = reviews))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    print("LOg In")
    error = None
    if request.method == 'POST':
        userid = request.form['userId']
        password = request.form['password']
        
        user = User(userid)
        
        if not user.verify_password(password):
            error = 'User Id or Password is Incorrect!'
        else:
            session["userid"] = userid
            flash("Logged in!")
            
            recommendations = Recommendations(userid)
            new_user = recommendations.check_if_newuser()
            
            if(new_user == "No"):
                listings, reviews = recommendations.collaborative_filtering()   
            else:
                listings, reviews = recommendations.random_recommendations()
                
            return(render_template('user.html', UserId = userid, new_user = new_user, listings = listings, reviews = reviews))
        
    return(render_template('login.html', error = error))


@app.route('/hostlogin', methods = ['GET', 'POST'])
def hostlogin():
    error = None
    if request.method == 'POST':
        hostid = request.form['hostid']
        password = request.form['password']
        
        host = Host(hostid)
        if not host.verify_password(password):
            error = 'User Id or Password is Incorrect!'
        else:
            session["hostid"] = hostid
            flash("Logged in!")
            
            return(render_template('hostlistingform.html', hostid = hostid))
    return(render_template('hostlogin.html', error = error))
            
@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    Print("Inside signup")
    error = None
    if request.method == 'POST':
        userid = request.form['userId']
        username = request.form['userName']
        password = request.form['password']
        
        if(len(password) < 5):
            error = "Your password must be at least 5 characters."
        elif(not User(userid).set_password(username, password)):
            error = "A user with that userid already exists."
        else:
            flash("Successfully Registered. Please login.")
            return(redirect(url_for('login_signup')))
        
    return(render_template('login.html', error_r = error))

@app.route('/hostsignup', methods = ['GET', 'POST'])
def hostsignup():
    error = None
    if request.method == 'POST':
        hostid = request.form['hostid']
        hostname = request.form['hostname']
        password = request.form['password']
        
        if(len(password) < 5):
            error = "Your password must be at least 5 characters."
        elif(not Host(hostid).set_password(hostname, password)):
            error = "A user with that userid already exists."
        else:
            flash("Successfully Registered. Please login.")
            return(render_template('hostdetails.html', hostid = hostid, hostname = hostname))
        
    return(render_template('hostlogin.html', error_r = error))

@app.route('/submithostdetails', methods = ['POST'])
def submithostdetails():
    if request.method == 'POST':
        hostid = request.form["hostid"]
        hostname = request.form["hostname"]
        image_url = request.form["image_url"]
        about = request.form["about"]
        identity_verified = request.form['identity_verified']
        location = request.form['location']
        
        host = Host(hostid)
        host.add_details(hostname, image_url, about, identity_verified, location)
        
        return(redirect(url_for('hostlogin_signup')))

@app.route("/logout")
def sign_out():
    if 'userid' in session:
        token = google_bp.token["access_token"]
        resp = google.post(
            "https://accounts.google.com/o/oauth2/revoke",
            params={"token": token},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        del google_bp.token
        session.pop('userid', None)
    session.pop("userid", None)
    return redirect(url_for("login"))

@app.route('/validatelocation', methods = ['GET', 'POST'])
def validate_location():
    error = None
    if request.method == 'POST':
        location = request.form['location']
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        guests = request.form.get('guests')
        print(guests)
        address = Address(location)
        
        if(address.check_location()):
            requirements = {"location" : location, "start_date" : start_date, "end_date" : end_date, "guests": guests}
            print(requirements)
            return(redirect(url_for('searchplace', requirements = requirements)))
        else:
            error = 'Invalid Location'
    return(render_template('user.html', error = error))
            
@app.route('/searchplace/<requirements>', methods = ['GET', 'POST'])
def searchplace(requirements, limit = 7):
    page = request.args.get(get_page_parameter(), 1, type = int)
    print(page)
    
    requirements = ast.literal_eval(requirements)
    print(requirements)
    
    location = requirements["location"]
    start_date = requirements["start_date"]
    end_date = requirements["end_date"]
    guests = requirements["guests"]
    
    address = Address(location)
    listings, reviews = address.get_listings(requirements)
    
    start = (page - 1) * limit
    end = page * limit if len(listings) > page * limit else len(listings)
        
    pagination = Pagination(page = page, total = len(listings))
        
    listings = dict(list(listings.items())[start: end])
    reviews = dict(list(reviews.items())[start : end])
        
    if(listings):
        return(render_template('search.html', UserId = session["userid"], location = location, 
                                   start_date = start_date, end_date = end_date, guests = guests,
                                   result = listings, result_r = reviews, paginate = pagination))
    
    return(redirect(url_for('searchplace', requirements = requirements)))

@app.route('/availablefilters', methods = ['GET', 'POST'])
def availablefilters():
    if request.method == 'POST':
        location = request.form['location']
        
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        guests = request.form.get('guests')
        
        cp = request.form["Cancellation_Policy"] #Cancellation Policy
        pt = request.form["Property_Type"]       #Property Type
        ib = request.form["Instant_Bookable"]    #Instant Bookable
        rt = request.form["Room_Type"]           #Room Type
        bt = request.form["Bed_Type"]            #Bed Type
        pr = request.form["Price"]               #Price
        filters = [cp, pt, ib, rt, bt, pr, start_date, end_date, guests]
        
        address = Address(location)
        filters_dict =  address.available_filters(filters)
        
        print(filters_dict)
        if(len(filters_dict) > 1):
            return(redirect(url_for('filters', filters = filters_dict)))
        else:
            requirements = {"location" : location, "start_date" : start_date, "end_date" : end_date, "guests": guests}
            return(redirect(url_for('searchplace', requirements = requirements)))
        
@app.route('/filters/<filters>', methods = ['GET', 'POST'])
def filters(filters, limit = 7):
    page = request.args.get(get_page_parameter(), 1, type = int)
    
    print(type(filters))
    filters = ast.literal_eval(filters)
    location = filters['neighbourhood']
    
    if("start_date" in filters.keys()):
        start_date = filters["start_date"]
    else:
        start_date = ''
        
    if("end_date" in filters.keys()):
        end_date = filters["end_date"]
    else:
        end_date = ''
        
    if("guests" in filters.keys()):
        guests = filters["guests"]
    else: guests = ''
    
    address = Address(location)
    
    listings, reviews = address.apply_filters(filters)
        
    start = (page - 1) * limit
    end = page * limit if len(listings) > page * limit else len(listings)
        
    pagination = Pagination(page = page, total = len(listings))
        
    listings = dict(list(listings.items())[start: end])
    reviews = dict(list(reviews.items())[start : end])
        
    if(listings):
        return(render_template('search.html', UserId = session["userid"], location = location, 
                               start_date = start_date, end_date = end_date, guests = guests,
                                   result = listings, result_r = reviews, paginate = pagination))
    requirements = {"location" : location, "start_date" : start_date, "end_date" : end_date, "guests": guests}
    return(redirect(url_for('searchplace', requirements = requirements)))
        
@app.route('/postreview', methods = ['GET', 'POST'])
def post_review():
    if request.method == 'POST':
        location = request.form['location']
        listing = request.form['listing']
        comment = request.form['review']
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        guests = request.form.get('guests')
        
        review = Reviews(listing, session["userid"], comment)
        review.create_review()
        
        requirements = {"location" : location, "start_date" : start_date, "end_date" : end_date, "guests": guests}
        return(redirect(url_for('searchplace', requirements = requirements)))

@app.route('/deletereview', methods = ['GET', 'POST'])
def delete_review():
    if request.method == 'POST':
        print("Inside delete Review")
        location = request.form['location']
        listing = request.form['listing']
        comment = request.form['comment']
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        guests = request.form.get('guests')
        
        review = Reviews(listing, session["userid"], comment)
        review.delete_review()
        
        requirements = {"location" : location, "start_date" : start_date, "end_date" : end_date, "guests": guests}
        return(redirect(url_for('searchplace', requirements = requirements)))
    
@app.route('/postreview_r', methods = ['GET', 'POST'])
def post_review_r():
    if request.method == 'POST':
        listing = request.form['listing']
        comment = request.form['review']
        
        review = Reviews(listing, session["userid"], comment)
        review.create_review()
        
        recommendations = Recommendations(session["userid"])
        new_user = recommendations.check_if_newuser()
            
        if(new_user == "No"):
            listings, reviews = recommendations.collaborative_filtering()   
        else:
            listings, reviews = recommendations.random_recommendations()
                
        return(render_template('user.html', UserId = session["userid"], new_user = new_user, listings = listings, reviews = reviews))

@app.route('/deletereview_r', methods = ['GET', 'POST'])
def delete_review_r():
    if request.method == 'POST':
        listing = request.form['listing']
        comment = request.form['comment']
        
        review = Reviews(listing, session["userid"], comment)
        review.delete_review()
        
        recommendations = Recommendations(session["userid"])
        new_user = recommendations.check_if_newuser()
            
        if(new_user == "No"):
            listings, reviews = recommendations.collaborative_filtering()   
        else:
            listings, reviews = recommendations.random_recommendations()
                
        return(render_template('user.html', UserId = session["userid"], new_user = new_user, listings = listings, reviews = reviews))
    
@app.route('/hostprofile/<hostid>', methods = ['GET', 'POST'])
def hostprofile(hostid):
    host = Host(hostid)
    host_information, listings= host.display_hostprofile()
    return(render_template('hostprofile.html', UserId = session["userid"], host_information = host_information, listings = listings))
 
@app.route('/submitlistingsdetails', methods = ['POST'])
def submit_listings():
    listing_id = request.form.get('listing_id')
    listing_name = request.form.get('listing_name')
    picture_url = request.form.get('picture_url')
    host_id = request.form.get('hostid')
    summary = request.form.get('summary')
    
    property_type = request.form.get('Property_type')
    room_type = request.form.get('Room_type')
    bed_type = request.form.get('Bed_type')
    
    no_of_beds = request.form.get('no_of_beds')
    no_of_bedrooms = request.form.get('no_of_bedrooms')
    no_of_accommodates = request.form.get('no_of_accommodates')
    
    price = request.form.get('price')
    cleaning_fee = request.form.get('cleaning_fee')
    security_deposit = request.form.get('security_deposit')
    monthly_price = request.form.get('montly_price')
    weekly_price = request.form.get('weekly_price')
    
    cancellation_policy = request.form.get('Cancellation_policy')
    instant_bookable = request.form.get('Instant_Bookable')
    
    availability_30 = request.form.get('availability_30')
    availability_60 = request.form.get('availability_60')
    availability_90 = request.form.get('availability_90')
    availability_365 = request.form.get('availability_365')
    
    neighbourhood = request.form.get('neighbourhood')
    
    listing_details = {"listing_id"          : listing_id, 
                       "listing_name"        : listing_name, 
                       "summary"             : summary, 
                       "picture_url"         : picture_url,
                       "host_id"             : host_id,
                       "property_type"       : property_type,
                       "room_type"           : room_type, 
                       "bed_type"            : bed_type, 
                       "no_of_beds"          : no_of_beds,
                       "no_of_bedrooms"      : no_of_bedrooms,
                       "no_of_accommodates"  : no_of_accommodates,
                       "price"               : price, 
                       "cleaning_fee"        : cleaning_fee,
                       "security_deposit"    : security_deposit, 
                       "monthly_price"        : monthly_price, 
                       "weekly_price"        : weekly_price,
                       "cancellation_policy" : cancellation_policy, 
                       "instant_bookable"    : instant_bookable, 
                       "availability_30"     : availability_30,
                       "availability_60"     : availability_60, 
                       "availability_90"     : availability_90,
                       "availability_365"    : availability_365, 
                       "neighbourhood"       : neighbourhood}
    print(listing_details)
    
    host = Host(host_id)
    host.add_listings_details(listing_details)
    
    return(redirect(url_for('index', submit = "Listing Successfully Created!")))
        
if __name__ == "__main__":
    app.run()


# In[ ]:




