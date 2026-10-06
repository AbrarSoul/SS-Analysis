""" Define the routes that add/delete comments on posts.

This includes:
  - /comment
  - /comments
  - /delete_comment
"""
import logging
from flask import request, Blueprint, g

from .. import permissions
from ..proxies import db_session, current_user
from ..models import Comment, Post, PageView
from ..utils.emails import send_comment_email

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

blueprint = Blueprint('comments', __name__,
                      template_folder='../templates', static_folder='../static')


@blueprint.route('/comment', methods=['POST'])
@PageView.logged
@permissions.post_comment.require()
def create_comment():
    """ Post a comment underneath a post """

    page_path = request.args.get('path', '')
    parent_id = request.args.get('comment_id')
    payload = request.get_json()

    target_post = (db_session.query(Post)
                             .filter(Post.path == page_path)
                             .first())

    if not target_post:
        raise Exception('Unable to find post')

    if parent_id:
        entry = (db_session.query(Comment)
                           .filter(Comment.id == parent_id)
                           .first())
    else:
        entry = Comment(post_id=target_post.id)

    entry.text = payload['text']
    entry.user_id = current_user.id
    db_session.add(entry)
    db_session.commit()

    send_comment_email(path=page_path,
                       commenter=current_user.format_name,
                       comment_text=payload['text'])
    return "OK"


@create_comment.object_extractor
def comment_reference():
    comment_id = request.args.get('comment_id', '')
    return {
        'id': comment_id if comment_id else None,
        'type': 'comment'
    }


@blueprint.route('/delete_comment')
@PageView.logged
@permissions.post_comment.require()
def delete_comment():
    """ Delete a comment """
    try:
        comment_id = int(request.args.get('comment_id', ''))

        comments = (db_session.query(Comment)
                              .filter(Comment.id == comment_id)
                              .all())
        for comment in comments:
            # you can only delete your own comments - silently fail on others
            if comment.user_id == current_user.id:
                db_session.delete(comment)
        db_session.commit()
    except:
        logging.warning("ERROR processing request")
        pass

    return ""


@delete_comment.object_extractor
def delete_comment():
    comment_id = request.args.get('comment_id', '')
    return {
        'id': int(comment_id) if comment_id else None,
        'type': 'comment',
        'action': 'delete'
    }
