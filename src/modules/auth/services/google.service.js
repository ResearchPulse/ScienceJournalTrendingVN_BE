import crypto from 'crypto';
import prisma from '../../../config/prisma.js';
import logger from '../../../utils/logger.js';
import axios from 'axios';
import { signChildAccessToken, signChildRefreshToken } from '../config/authTokens.js';

/**
 * Tạo token JWT để duy trì phiên đăng nhập cho user
 * @param {Object} user - Đối tượng user cần tạo token
 * @param {string} user.user_id - ID của user
 * @param {string} user.email - Email của user
 * @param {string} user.role - Vai trò của user
 * @returns {string} Chuỗi JWT token
 * @throws {Error} Ném lỗi nếu chưa định nghĩa JWT_SECRET trong biến môi trường
 */
const signToken = (user) => {
  return signChildAccessToken(user);
};

/**
 * Xác thực Google ID Token gửi từ phía client bằng cách gọi trực tiếp Google Tokeninfo API
 * @param {string} idToken - Chuỗi Google ID Token nhận từ phía client
 * @returns {Promise<Object>} Trả về thông tin payload của user từ Google nếu token hợp lệ
 * @throws {Error} Ném lỗi 400 nếu token không hợp lệ hoặc lỗi 500 nếu không thể kết nối tới Google API
 */
export const verifyGoogleIdToken = async (idToken) => {
  try {
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      const error = new Error(errData.error_description || 'Mã xác thực Google không hợp lệ');
      error.statusCode = 400;
      throw error;
    }
    return await response.json();
  } catch (err) {
    if (err.statusCode) throw err;
    const error = new Error('Không thể kết nối đến dịch vụ xác thực Google');
    error.statusCode = 500;
    throw error;
  }
};

/**
 * Thực hiện đăng nhập hoặc đăng ký t� i khoản tự động khi xác thực bằng Google ID Token
 * @param {string} idToken - Chuỗi Google ID Token nhận từ phía client
 * @returns {Promise<Object>} Trả về đối tượng chứa JWT access token v�  thông tin chi tiết người dùng
 * @throws {Error} Ném lỗi 403 nếu t� i khoản bị khóa (BANNED) hoặc lỗi validation khác
 */
export const loginOrCreateWithGoogle = async (idToken) => {
  if (!idToken || !idToken.trim()) {
    const error = new Error('Token xác thực Google không được để trống');
    error.statusCode = 400;
    throw error;
  }

  // 1. Xác thực ID Token với Google
  const googleUser = await verifyGoogleIdToken(idToken);
  const email = googleUser.email.trim().toLowerCase();

  // 2. Tìm xem email đã tồn tại trong DB chưa
  let user = await prisma.user.findFirst({
    where: {
      email: {
        equals: email,
        mode: 'insensitive'
      }
    }
  });

  if (user) {
    // Nếu t� i khoản bị khóa
    if (user.status === 'BANNED') {
      const error = new Error('T� i khoản đã bị khóa');
      error.statusCode = 403;
      throw error;
    }

    // Nếu trạng thái l�  INACTIVE hoặc auth_provider chưa phải GOOGLE, cập nhật lại
    if (user.status === 'INACTIVE' || user.type !== 'GOOGLE') {
      user = await prisma.user.update({
        where: { user_id: user.user_id },
        data: {
          status: 'ACTIVE',
          type: 'GOOGLE'
        }
      });
    }
  } else {
    // Đăng ký mới t� i khoản bằng Google
    user = await prisma.user.create({
      data: {
        user_id: crypto.randomUUID(),
        email: email,
        type: 'GOOGLE',
        status: 'ACTIVE',
        role: 'STUDENT',
        first_name: googleUser.given_name || null,
        last_name: googleUser.family_name || null,
        url_image: googleUser.picture || null
      }
    });
  }

  const token = signToken(user);
  const refreshToken = signChildRefreshToken(user);

  return {
    token,
    refreshToken,
    user: {
      user_id: user.user_id,
      email: user.email,
      role: user.role
    }
  };
};

/**
 * H� m đổi Authorization Code lấy id_token từ Google
 * @param {string} code - Mã code nhận từ useGoogleLogin (chuỗi 4/0A...)
 * @returns {Promise<string|null>} - Trả về chuỗi id_token (JWT) nếu th� nh công
 */
export const getTokenId = async (code) => {
  // 1. Cấu hình các thông số cần thiết
  const tokenUrl = process.env.TOKEN_URL;

  const payload = {
    code: code,
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uri: process.env.FRONTEND_URL,
    grant_type: 'authorization_code',
  };

  try {
    // 2. Thực hiện gọi API với định dạng x-www-form-urlencoded
    const response = await axios.post(tokenUrl, payload, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    // 3. Google trả về data th� nh công, lấy ra id_token
    if (response.data && response.data.id_token) {
      console.log('Lấy id_token th� nh công!');
      return response.data.id_token; // Đây l�  chuỗi JWT bạn cần đem về Backend
    }

    return null;
  } catch (error) {
    logger.error(
      'Lỗi khi đổi code lấy id_token:',
      error.response?.data || error.message
    );
    throw error;
  }
};
