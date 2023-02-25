const User = require("../model/user");
const VerificationToken = require("../model/verificationToken");
const ResetToken = require("../model/resetToken");
const { sendError, createRandomBytes } = require("../utils/helper");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const {
  generateOTP,
  mailTransport,
  generateEmailTemplate,
  plainEmailTemplate,
  generatePasswordResetTemplate,
} = require("../utils/mail");
const { isValidObjectId } = require("mongoose");

exports.createUser = async (req, res) => {
  const { name, email, password } = req.body;
  const user = await User.findOne({ email });
  if (user) return sendError(res, "This email already exists !");

  const newUser = new User({
    name,
    email,
    password,
  });

  const OTP = generateOTP();
  const verificationToken = new VerificationToken({
    owner: newUser._id,
    token: OTP,
  });

  await verificationToken.save();
  await newUser.save();

  mailTransport().sendMail({
    from: "emailverification@email.com",
    to: newUser.email,
    subject: "Verify your email account",
    html: generateEmailTemplate(OTP),
  });

  res.json({
    success: true,
    user: {
      name: newUser.name,
      email: newUser.email,
      id: newUser._id,
      verified: newUser.verified,
    },
  });
};

exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email.trim() || !password.trim())
      return sendError(res, "email/password missing");

    const user = await User.findOne({ email });
    if (!user) return sendError(res, "User not found !");

    const isMatched = await user.comparePassword(password);
    if (!isMatched) return sendError(res, "email/password does not match !");

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({
      success: true,
      user: { name: user.name, email: user.email, id: user._id, token },
    });
  } catch (error) {
    sendError(res, error.message, 500);
  }
};

exports.verifyEmail = async (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp.trim())
    return sendError(res, "Invalid request, missing parameters !");

  if (!isValidObjectId(userId)) return sendError(res, "Invalid User ID !");

  const user = await User.findById(userId);

  if (!user) return sendError(res, "Error, User not found !");

  if (user.verified)
    return sendError(res, "This account is already verified !");

  const token = await VerificationToken.findOne({ owner: user._id });
  if (!token) return sendError(res, "Sorry User Not found !");

  const isMatched = await token.compareToken(otp);
  if (!isMatched) return sendError(res, "Please provide a valid Token !");

  user.verified = true;

  await VerificationToken.findByIdAndDelete(token._id);
  await user.save();

  mailTransport().sendMail({
    from: "emailverification@email.com",
    to: user.email,
    subject: "Welcome email",
    html: plainEmailTemplate(
      "Email verified Successfully",
      "Thanks for connecting with us"
    ),
  });

  res.json({
    success: true,
    message: "your email is verified.",
    user: { name: user.name, email: user.email, id: user._id },
  });
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) return sendError(res, "Please provide a valid email !");

  const user = await User.findOne({ email });
  if (!user) return sendError(res, "User not found, invalid request !");

  const token = await ResetToken.findOne({ owner: user._id });
  if (token)
    return sendError(
      res,
      "Only after one hour you can request for another token !"
    );

  const randomBytes = await createRandomBytes();
  const resetToken = new ResetToken({ owner: user._id, token: randomBytes });
  await resetToken.save();

  mailTransport().sendMail({
    from: "security@email.com",
    to: user.email,
    subject: "Password reset email",
    html: generatePasswordResetTemplate(
      `http://localhost:3000/reset-password?token=${randomBytes}&id=${user._id}`
    ),
  });

  res.json({
    success: true,
    message: "Password reset link is sent to your email.",
  });
};

exports.resetPassword = async (req, res) => {
  const { password } = req.body;

  const user = await User.findById(req.user._id);
  if (!user) return sendError(res, "User not found !");

  const isSamePassword = await user.comparePassword(password);
  if (isSamePassword) return sendError(res, "Don't use old passwords !");

  if (password.trim().length < 8 || password.trim().length > 20)
    return sendError(res, "Password must be 8 to 20 characters long !");

  user.password = password.trim();
  await user.save();

  await ResetToken.findOne({ owner: user._id });

  mailTransport().sendMail({
    from: "security@email.com",
    to: user.email,
    subject: "Password reset successfully",
    html: plainEmailTemplate(
      "Password Reset Successfully",
      "Now you can login with new password !"
    ),
  });
  res.json({
    success: true,
    message: "Password reset Successful.",
  });
};
