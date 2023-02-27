@route.get("/google", include_in_schema=False)
async def google(request: Request):
    GOOGLE_CLIENT_ID = setting.GOOGLE_CLIENT_ID
    GOOGLE_CLIENT_SECRET = setting.GOOGLE_CLIENT_SECRET

    CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"

    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={"scope": "openid email profile"},
    )

    # TODO: we need to test it
    redirect_uri = (
        f"{request.url.scheme}://{request.url.hostname}:{request.url.port}/google_auth"
    )
    # redirect_uri = request.url_for("google_auth")

    return await oauth.google.authorize_redirect(request, redirect_uri)


@route.route("/google_auth", include_in_schema=False)
async def google_auth(request: Request):
    try:
        access_token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=OAuthError.error,
        )

    user = access_token["userinfo"]
    email = user["email"]

    provider_type = SocialLoginProviderType.google.value
    provider_key = user["sub"]

    db = SessionLocal()

    user, is_company = get_user_by_email(db, email)

    if user:
        if user.provider_type.value == provider_type:
            if user.provider_key == provider_key:
                return RedirectResponse(url=f"/auth/social?email={email}")
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Provider key is not valid",
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This email is not for Google login",
            )
    else:
        row = User(email=email, provider_key=provider_key, provider_type=provider_type)

        db.add(row)
        db.commit()
        db.refresh(row)

    return RedirectResponse(url=f"/auth/social?email={email}")


@route.get("/social", include_in_schema=False)
def social(email: str, db: Session = Depends(get_db)):
    user, is_company = get_user_by_email(db, email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The email is not valid",
        )

    if is_company:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The company user is not allowed",
        )

    company_id = user.company_id

    token = create_access_token({"user_id": user.id, "company_id": company_id})

    return UserTokenSchema(
        token=token,
        apikey=user.apikey,
        phone=user.ph,
        email=user.email,
        role=user.role,
    )


@route.get("/facebook")
async def facebook(request: Request):
    FACEBOOK_CLIENT_ID = setting.FACEBOOK_CLIENT_ID
    FACEBOOK_CLIENT_SECRET = setting.FACEBOOK_CLIENT_SECRET

    oauth.register(
        name="facebook",
        client_id=FACEBOOK_CLIENT_ID,
        client_secret=FACEBOOK_CLIENT_SECRET,
        access_token_url="https://graph.facebook.com/oauth/access_token",
        access_token_params=None,
        authorize_url="https://www.facebook.com/dialog/oauth",
        authorize_params=None,
        api_base_url="https://graph.facebook.com/",
        client_kwargs={"scope": "email"},
    )

    redirect_uri = f"{request.url.scheme}://{request.url.hostname}:{request.url.port}/facebook_auth"
    # redirect_uri = request.url_for("facebook_auth")

    return await oauth.facebook.authorize_redirect(redirect_uri)


@route.route("/facebook_auth")
async def facebook_auth(request: Request):
    try:
        access_token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=OAuthError.error,
        )

    user = access_token["userinfo"]
    email = user["email"]

    provider_type = SocialLoginProviderType.facebook.value
    provider_key = user["sub"]

    db = SessionLocal()

    user, is_company = get_user_by_email(db, email)

    if user:
        if user.provider_type.value == provider_type:
            if user.provider_key == provider_key:
                return RedirectResponse(url=f"/auth/social?email={email}")
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Provider key is not valid",
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This email is not for Facebook login",
            )
    else:
        row = User(email=email, provider_key=provider_key, provider_type=provider_type)

        db.add(row)
        db.commit()
        db.refresh(row)

    return RedirectResponse(url=f"/auth/social?email={email}")
